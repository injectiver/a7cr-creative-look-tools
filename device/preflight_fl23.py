"""A7CR check-only preparation adapted from the two supplied repositories.

This CLI has no install/restore command. It stages only the two mode-0-only
workers, verifies unchanged complete programs/settings, and reads only the CP
units required by the A7CR notes (unit01/unit0d). Native temporary files are
created; camera firmware, saved settings and WBI state are not changed.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from datetime import datetime, timezone

from read_backup import ROOT, Reader, backup_sections, private_owner, CP_UNITS
sys.path.insert(0, str(ROOT / "offline"))
from inspect_sources import save_json

TEMP = frozenset(("libJit.so", "a7cr.check-program.so", "a7cr.check-wbi.so",
                  "a7cr.install.request", "a7cr.install.result", "a7cr.wbi.request", "a7cr.wbi.result"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeCheckRejected(ValueError):
    pass


class CheckSession(Reader):
    def temp_command(self, command, payload):
        if command not in (15, 16, 17, 18):
            raise ValueError("Unsupported temporary operation")
        result, raw = self.call(f"PREFLIGHT_TEMP_{command}", self.channel.sendSenserPacket,
                                0x40, struct.pack("<HH", 0x1001, command)+payload)
        if result or len(raw) < 4:
            self.healthy = False
            raise ValueError("Malformed temporary file response")
        return struct.unpack_from("<I", raw)[0], raw[4:]

    def select_temp(self, name):
        if name not in TEMP:
            raise ValueError("Unowned temporary file")
        status, _ = self.temp_command(15, b"\0/tmp/jiritsu/"+name.encode()+b"\0")
        if status:
            self.healthy = False
            raise ValueError("Temporary path selection failed")

    def read_temp(self, name, optional=False):
        self.select_temp(name)
        status, raw = self.temp_command(17, b"\0\xff\0")
        if optional and status == 0x10000006:
            return None
        if status:
            self.healthy = False
            raise ValueError("Temporary read failed")
        return raw

    def write_temp(self, name, raw, expected):
        if name not in expected or expected[name] != raw or not raw or len(raw) > 65536:
            raise ValueError("Unreviewed temporary contents")
        self.select_temp(name)
        status, _ = self.temp_command(16, b"\0\xff\0"+raw)
        if status:
            self.healthy = False
            raise ValueError("Temporary staging/invocation failed")

    def remove_temp(self, name, expected):
        actual = self.read_temp(name, True)
        if actual is None:
            return
        if actual != expected[name]:
            raise ValueError("Preserve unexpected temporary contents")
        self.select_temp(name)
        status, _ = self.temp_command(18, b"\0\xff")
        if status or self.read_temp(name, True) is not None:
            self.healthy = False
            raise ValueError("Temporary cleanup incomplete")

    def check_preload(self):
        path = b"\0/tmp/jiritsu/../../etc/ld.so.preload\0"
        status, _ = self.temp_command(15, path)
        if status:
            self.healthy = False
            raise ValueError("Preload inspection selection failed")
        status, raw = self.temp_command(17, b"\0\xff\0")
        if status == 0x10000006:
            return
        if status or raw:
            raise ValueError("Existing/unknown preload state requires inspection")

    def required_cp_read(self, key):
        sizes = {0x02A40001: 8192, 0x02A4000D: 28672}
        if key not in sizes:
            raise ValueError("Only the two documented FL23 units can be probed")
        previous_budget = getattr(self.backend, "operation_budget_seconds", 180)
        self.backend.operation_budget_seconds = 20
        try:
            raw = self.call(f"REQUIRED_CP_READ40_{key:08x}", self.camera._sendAdjustControlPacket,
                            0x603, 0x40, struct.pack("<II", key, 1))
        finally:
            self.backend.operation_budget_seconds = previous_budget
        if len(raw) != sizes[key]:
            raise ValueError("Required CP unit length differs")
        return raw


def decode_program(raw, audit):
    if len(raw) != 240:
        raise ValueError("Unexpected program report length")
    values = struct.unpack("<8s4I7q4Q64s64s", raw)
    if values[:3] != (b"A7IRP001", 1, 0) or values[4] != 0:
        raise ValueError("Unexpected native mode/ABI/write count")
    expected = b"".join(bytes.fromhex(audit["programs"][kind]["source_sha256"]) for kind in ("AP", "CP"))
    ok = (values[3] == 9 and values[5] == 0 and all(values[index] == 0 for index in (6, 7, 8, 9, 10))
          and all(values[index] > 0 for index in (11, 12, 13)) and values[16] == expected
          and values[17] == bytes(64)
          and values[14:16] == tuple(audit["programs"][kind]["bytes"] for kind in ("AP", "CP")))
    return {"ok": ok, "phase": values[3], "writes": values[4], "status": values[5],
            "readonly_status": values[8], "cleanup": values[9], "euid": values[10]}


def decode_wbi(raw):
    if len(raw) != 192:
        raise ValueError("Unexpected WBI report length")
    values = struct.unpack("<8sII9q16s16s32s32sII", raw)
    if values[:3] != (b"A7WBR001", 1, 0) or any(values[index] for index in (7, 8, 9, 10)):
        raise ValueError("Unexpected WBI mode/ABI/write count")
    ok = (values[3] == 0 and values[4] == 0 and values[5] == 0 and values[6] > 0
          and values[11] == 0 and values[13] == bytes(16) and values[15] == bytes(32)
          and values[16:] == (0, 0)
          and values[12].rstrip(b"\0") == b"2\n" and values[14].rstrip(b"\0") == b"*wbi4\n")
    return {"ok": ok, "status": values[3], "euid": values[5],
            "image_mode": values[12].rstrip(b"\0").decode("ascii", "replace"),
            "image_dev": values[14].rstrip(b"\0").decode("ascii", "replace"), "writes": 0}


def invoke_check(camera, kind, blob, workspace, record, audit):
    if kind == "program_check":
        stage, request, result, magic = "a7cr.check-program.so", "a7cr.install.request", "a7cr.install.result", b"A7INS001"
        decode = lambda raw: decode_program(raw, audit)
    elif kind == "wbi_check":
        stage, request, result, magic = "a7cr.check-wbi.so", "a7cr.wbi.request", "a7cr.wbi.result", b"A7WBI001"
        decode = decode_wbi
    else:
        raise ValueError("Only check-only workers may be invoked")
    request_bytes = struct.pack("<8sII", magic, 0, 0)
    expected = {stage: blob, request: request_bytes, "libJit.so": blob}
    for name in (stage, request, result, "libJit.so"):
        if camera.read_temp(name, True) is not None:
            raise ValueError("Existing native state; no new invocation")
    camera.check_preload()
    for name in (stage, request):
        record("native_staging_intent", worker=kind, name=name)
        camera.write_temp(name, expected[name], expected)
        if camera.read_temp(name) != expected[name]:
            raise ValueError("Staged native bytes differ")
    record("native_check_invocation_intent", worker=kind, mode=0, sha256=sha(blob))
    try:
        camera.write_temp("libJit.so", blob, expected)
        raw = camera.read_temp(result)
        path = workspace / (kind+".result.private.bin")
        path.write_bytes(raw); private_owner(path)
        parsed = decode(raw)
    except BaseException:
        camera.healthy = False
        raise
    expected[result] = raw
    record("native_check_returned", worker=kind, report=parsed)
    for name in ("libJit.so", result, request, stage):
        camera.remove_temp(name, expected)
    record("native_check_cleanup_verified", worker=kind)
    if not parsed["ok"]:
        raise NativeCheckRejected(f"{kind} did not pass: {parsed}")
    return parsed


def compare_settings(before, after):
    for key in CP_UNITS:
        if before[1][key] != after[1][key]:
            raise ValueError("A protected CP unit changed during checks")
    select = lambda state: {key: (value.data, value.attr) for key, value in state[0].items()
                            if key >> 16 == 0x02CF and key != 0x02CF0B6E}
    if select(before) != select(after):
        raise ValueError("A writable look setting changed during checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("Mac USB capture requires sudo in your terminal")
    os.umask(0o077)
    workspace = args.workspace.resolve()
    parent = ROOT / "private/preflight"
    if workspace.parent != parent.resolve():
        raise ValueError("Use a fresh direct job directory under private/preflight")
    parent.mkdir(parents=True, exist_ok=True); private_owner(parent, True)
    workspace.mkdir(parents=True, exist_ok=False); private_owner(workspace, True)
    audit = json.loads((ROOT / "private/offline/fl23-candidate/audit.private.json").read_text())
    workers = json.loads((ROOT / "private/native-workers/workers.private.json").read_text())
    if not workers["native_simulation_passed"] or workers["synthetic_case_count"] < 14:
        raise ValueError("Native offline checks have not passed")
    blobs = {}
    for kind in ("program_check", "wbi_check"):
        spec = workers["workers"][kind]; blob = (ROOT / spec["file"]).read_bytes()
        if len(blob) != spec["bytes"] or sha(blob) != spec["sha256"]:
            raise ValueError("Prepared native worker changed")
        blobs[kind] = blob
    events = []
    def record(phase, **detail):
        events.append({"phase": phase, "utc": datetime.now(timezone.utc).isoformat(), **detail})
        path = workspace / "events.private.json"; save_json(path, events); private_owner(path)
    def snapshot(camera, memory, tag):
        raw = camera.snapshot(memory); path = workspace / (tag+".private.bin")
        path.write_bytes(raw); private_owner(path)
        return backup_sections(raw)
    try:
        with (ROOT / "private/device.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with CheckSession(record, mac_capture=True) as camera:
                binding = workers["body_binding"]
                if camera.identity["usb_serial_sha256"] != binding["usb_serial_sha256"]:
                    raise ValueError("Connected body differs from the captured backup")
                record("body_identified", identity=camera.identity)
                for kind, path in (("AP", "/usr/lib/appFw.so"), ("CP", "/cp/cpapp-b.bin")):
                    raw = camera.read_program(path)
                    if sha(raw) != audit["programs"][kind]["source_sha256"]:
                        raise ValueError("Fresh program bytes differ from the reviewed body input")
                ram = snapshot(camera, True, "memory-before"); saved = snapshot(camera, False, "flash-before")
                ap_serial = ram[0][0x00E70003].data
                if (len(ap_serial) != 4 or ap_serial != saved[0][0x00E70003].data
                        or sha(ap_serial.hex().encode("ascii")) != binding["ap_serial_sha256"]):
                    raise ValueError("AP backup identity differs from the captured body")
                native = {}
                for kind in ("program_check", "wbi_check"):
                    print("运行仅校验模块："+kind, flush=True)
                    native[kind] = invoke_check(camera, kind, blobs[kind], workspace, record, audit)
                for key in (0x02A40001, 0x02A4000D):
                    print(f"核对文档要求的 CP 单元：{key:08x}（最多等待20秒）", flush=True)
                    raw = camera.required_cp_read(key)
                    if raw != ram[1][key].data or raw != saved[1][key].data:
                        raise ValueError("Required CP read and complete snapshots differ")
                    record("required_cp_read_verified", key=f"{key:08x}", bytes=len(raw), sha256=sha(raw))
                after_ram = snapshot(camera, True, "memory-after"); after_saved = snapshot(camera, False, "flash-after")
                compare_settings(ram, after_ram); compare_settings(saved, after_saved)
                for kind, path in (("AP", "/usr/lib/appFw.so"), ("CP", "/cp/cpapp-b.bin")):
                    if sha(camera.read_program(path)) != audit["programs"][kind]["source_sha256"]:
                        raise ValueError("Complete program changed during preflight")
                record("unchanged_programs_and_settings_verified")
        result = {"schema": "a7cr-device-preflight/1", "phase": "CAMERA_CHECKS_PASSED_NOT_INSTALLED",
                  "body_identity": camera.identity, "native_reports": native,
                  "firmware_or_settings_written": False, "wbi_modified": False,
                  "temporary_native_modules_executed": True, "required_cp_units_verified": ["02a40001", "02a4000d"]}
        path = workspace / "preflight.private.json"; save_json(path, result); private_owner(path)
        record("complete")
        print(json.dumps({"phase": result["phase"], "workspace": str(workspace), "firmware_written": False}, indent=2))
    except BaseException as error:
        record("stopped_no_retry", error_type=type(error).__name__, error=str(error))
        raise


if __name__ == "__main__":
    main()
