"""Read disk, saved/live parameters and fixed loaded AP spans. No reinstall.

Uploads one reviewed temporary read-only diagnostic. It cannot write firmware,
saved parameters, WBI, process memory or raw devices. Ambiguous results stop.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import struct
from datetime import datetime, timezone

from fl23_install import Package, Job, OWNED, PATHS, CP_KEYS, AP_KEYS, durable_json, store_private
from read_backup import ROOT, private_owner
from preflight_fl23 import CheckSession, sha

EXTRA = frozenset(("a7cr.diag-staged.so", "a7cr.diag.probe.result", "a7cr.diag.runtime.result"))
NAMES = OWNED | EXTRA
WORKSPACE = ROOT / "private/install/20261020-a7cr-fl23-01"


class DiagnosticSession(CheckSession):
    def __init__(self, package, record):
        super().__init__(record, mac_capture=True)

    def select_temp(self, name):
        if name not in NAMES:
            raise ValueError("Unowned diagnostic path")
        status, _ = self.temp_command(15, b"\0/tmp/jiritsu/"+name.encode()+b"\0")
        if status:
            self.healthy = False
            raise ValueError("Diagnostic path selection failed")


def decode_probe(raw):
    if len(raw) < 72:
        raise ValueError("Truncated diagnostic maps report")
    v = struct.unpack_from("<8sII4qQ4I", raw)
    if (v[:3] != (b"A7PRB001", 1, 0) or v[11] != 0
            or len(raw) != 72+sum(v[8:11]) or v[4] != 0 or v[5] <= 0):
        raise ValueError("Unexpected diagnostic maps ABI/identity")
    return {"status": v[3], "euid": v[4], "pid": v[5], "cleanup": v[6], "base": v[7],
            "maps_bytes": v[8], "mounts_bytes": v[9], "cmdline_bytes": v[10]}


def decode_runtime(raw, spans, package):
    count=len(spans)
    if not 8<=count<=24 or len(raw) != 56+count*256+240:
        raise ValueError("Unexpected runtime diagnostic length")
    v = struct.unpack_from("<8sII3qQII", raw)
    if v[:3] != (b"A7CRR001", 1, count) or v[4] != 0 or v[5] <= 0 or v[7:] != (0, 0):
        raise ValueError("Unexpected runtime diagnostic ABI/identity")
    items = []
    for index, span in enumerate(spans):
        at, length = span["offset"], span["bytes"]
        if not 0 < length <= 128:
            raise ValueError("Unreviewed runtime span")
        live = raw[56+index*256:56+index*256+length]
        disk = raw[56+index*256+128:56+index*256+128+length]
        classify = lambda value: next((key for key in ("candidate", "original")
                                      if value == package.programs[key]["AP"][at:at+length]), "other")
        items.append({"name": span["name"], "offset": at, "bytes": length,
                      "loaded_state": classify(live) if v[3] == 0 else "read_failed",
                      "disk_state": classify(disk) if v[3] == 0 else "read_failed",
                      "loaded_hex": live.hex(), "disk_hex": disk.hex()})
    text_at = 56+count*256
    field = lambda start, size: raw[text_at+start:text_at+start+size].split(b"\0", 1)[0].decode("ascii", "replace")
    mode, device, uptime, boot_id = field(0, 16), field(16, 32), field(48, 128), field(176, 64)
    formats_ok = (mode in ("0\n", "2\n") and device == "*wbi4\n"
                  and re.fullmatch(r"[0-9]+(?:\.[0-9]+)? [0-9]+(?:\.[0-9]+)?\n", uptime) is not None
                  and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", boot_id) is not None)
    return {"ok": v[3] == 0 and v[6] > 0 and formats_ok, "native_status": v[3],
            "pid": v[5], "base": v[6], "image_mode": mode, "image_dev": device,
            "uptime": uptime, "boot_id": boot_id, "spans": items,
            "all_loaded_ap_spans_match_candidate": v[3] == 0 and all(item["loaded_state"] == "candidate" for item in items),
            "running_cp_memory_read": False}


def invoke(camera, blob, spans, package, attempt, record):
    for name in sorted(NAMES):
        if camera.read_temp(name, True) is not None:
            raise ValueError("Existing native temporary state; preserve it before new diagnostics")
    camera.check_preload()
    expected = {"a7cr.diag-staged.so": blob, "libJit.so": blob}
    camera.write_temp("a7cr.diag-staged.so", blob, expected)
    if camera.read_temp("a7cr.diag-staged.so") != blob:
        raise ValueError("Staged read-only diagnostic differs")
    record("runtime_readonly_invocation_intent", sha256=sha(blob), persistent_camera_writes=False)
    try:
        camera.write_temp("libJit.so", blob, expected)
        for name in ("a7cr.diag.probe.result", "a7cr.diag.runtime.result"):
            raw = camera.read_temp(name)
            store_private(attempt / (name+".private.bin"), raw)
            expected[name] = raw
        probe = decode_probe(expected["a7cr.diag.probe.result"])
        runtime = decode_runtime(expected["a7cr.diag.runtime.result"], spans, package)
        if (probe["base"] != runtime["base"] or probe["pid"] != runtime["pid"]
                or probe["cleanup"] or (probe["status"] and probe["status"] != runtime["native_status"])):
            raise ValueError("Diagnostic reports do not describe the same process/outcome")
    except BaseException:
        camera.healthy = False
        raise
    record("runtime_readonly_invocation_returned", probe=probe, runtime=runtime)
    for name in ("libJit.so", "a7cr.diag.runtime.result", "a7cr.diag.probe.result", "a7cr.diag-staged.so"):
        camera.remove_temp(name, expected)
    record("runtime_readonly_cleanup_verified")
    return runtime


def parameter_report(package, snapshots):
    result = {}
    for source, sections in snapshots.items():
        result[source] = {
            "ap_bindings": {f"{key:08x}": {"actual_hex": sections[0][key].data.hex(),
                                           "expected_hex": package.bindings["candidate"][key].hex(),
                                           "matches": sections[0][key].data == package.bindings["candidate"][key]}
                            for key in AP_KEYS},
            "cp_units": {f"{key:08x}": {"bytes": len(sections[1][key].data), "sha256": sha(sections[1][key].data),
                                         "matches": sections[1][key].data == package.units["candidate"][key]}
                         for key in CP_KEYS},
        }
    return result


def main():
    if os.geteuid() != 0:
        raise PermissionError("Use sudo in your terminal for Mac USB capture")
    os.umask(0o077)
    package = Package(WORKSPACE)
    manifest = json.loads((ROOT / "private/runtime-diagnostic/runtime.private.json").read_text())
    if not manifest["simulation_passed"]:
        raise ValueError("Read-only runtime diagnostic has not passed offline simulation")
    spec = manifest["worker"]; blob = (ROOT / spec["file"]).read_bytes()
    if len(blob) != spec["bytes"] or sha(blob) != spec["sha256"]:
        raise ValueError("Reviewed diagnostic worker changed")
    with (ROOT / "private/device.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        attempt = package.root / ("diagnose-"+stamp)
        attempt.mkdir(exist_ok=False); private_owner(attempt, True)
        job = Job(package, attempt)
        try:
            job.record("readonly_diagnosis_started", persistent_camera_writes=False)
            with DiagnosticSession(package, job.record) as camera:
                job.body(camera)
                versions = {}
                for kind, path in PATHS.items():
                    raw = camera.read_program(path)
                    versions[kind] = next((direction for direction in ("candidate", "original")
                                           if raw == package.programs[direction][kind]), "other")
                    job.record("diagnostic_full_program_readback", component=kind, bytes=len(raw), sha256=sha(raw), state=versions[kind])
                    if versions[kind] == "other":
                        store_private(attempt / ("unexpected-"+kind+".private.bin"), raw)
                        raise ValueError("Unknown disk bytes; preserve the readback before injecting a diagnostic")
                current = job.snapshots(camera, "diagnostic-before")
                parameters = parameter_report(package, current)
                cp_live = {}
                for key in CP_KEYS:
                    raw = camera.required_cp_read(key)
                    cp_live[f"{key:08x}"] = {"sha256": sha(raw), "matches_candidate": raw == package.units["candidate"][key],
                                            "matches_snapshot": raw == current["memory"][1][key].data}
                print("读取运行中的 AP 代码、启动状态和已保存参数；不刷写固件。", flush=True)
                runtime = invoke(camera, blob, manifest["spans"], package, attempt, job.record)
            result = {"schema": "a7cr-fl23-behavior-diagnosis/1", "phase": "READONLY_DIAGNOSIS_CAPTURED",
                      "disk_programs": versions, "parameters": parameters, "direct_cp_reads": cp_live,
                      "loaded_ap": runtime, "firmware_settings_or_wbi_written": False,
                      "temporary_readonly_module_executed": True, "new_photo_color_effect_proven": False}
            durable_json(attempt / "diagnosis.private.json", result)
            job.record("readonly_diagnosis_complete", normal_usb_return_confirmed=True)
            print(json.dumps({"phase": result["phase"], "attempt": str(attempt),
                              "disk_programs": versions, "loaded_ap_matches_candidate": runtime["all_loaded_ap_spans_match_candidate"],
                              "image_mode": runtime["image_mode"], "native_status": runtime["native_status"],
                              "firmware_settings_or_wbi_written": False}, indent=2), flush=True)
        except BaseException as error:
            job.record("stopped_no_retry", error_type=type(error).__name__, error=str(error))
            print("诊断已停止；请保留输出，不要重复刷写。", flush=True)
            raise


if __name__ == "__main__":
    main()
