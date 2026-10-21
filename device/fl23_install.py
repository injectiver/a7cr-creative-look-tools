"""Body-bound A7CR FL23 install/inspection/rollback; never an official update.

Native workers and Backup protocol are adapted from QAQLeonard's MIT-licensed
a7c2-fl23-research. A7CR offsets/order come from lzh2016zzz/a7cr-fl23-research.
No automatic retry, resume, firmware download, raw-flash write or reboot.
The explicit complete-ap command accepts only the reviewed CP-complete stop.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import struct
import sys

from preflight_fl23 import CheckSession, TEMP, sha, decode_program, decode_wbi, NativeCheckRejected
from read_backup import ROOT, backup_sections, private_owner, CP_UNITS
from inspect_sources import save_json

CP_KEYS = (0x02A40001, 0x02A4000D)
AP_KEYS = (0x02CF1287, 0x02CF1289)
OWNED = TEMP | frozenset(("a7cr.stage.so",))
PATHS = {"AP": "/usr/lib/appFw.so", "CP": "/cp/cpapp-b.bin"}
AP_DIAGNOSTIC = 0x02CF0B6E
REVIEWED_STOP = "Unrelated property changed: chip0/02770015"


def durable_json(path, value):
    save_json(path, value)
    private_owner(path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def store_private(path, raw):
    with path.open("xb") as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    private_owner(path)


class Package:
    def __init__(self, workspace):
        self.root = workspace.resolve()
        if self.root.parent != (ROOT / "private/install").resolve():
            raise ValueError("Installation job must be a direct directory under private/install")
        self.manifest = json.loads((self.root / "package.private.json").read_text())
        if self.manifest["schema"] != "a7cr-fl23-local-installation/1":
            raise ValueError("Unknown installation package")
        self.binding = self.manifest["body_binding"]
        self.audit = self.manifest["audit"]
        self.blobs = {}
        for name, spec in self.manifest["files"].items():
            path = (self.root / spec["file"]).resolve()
            if path.parent != (self.root / "payload").resolve():
                raise ValueError("Payload escapes the private job")
            raw = path.read_bytes()
            if len(raw) != spec["bytes"] or sha(raw) != spec["sha256"]:
                raise ValueError("Prepared payload changed: " + name)
            self.blobs[name] = raw
        self.programs = {direction: {kind: self.blobs[f"{direction}-{kind}"] for kind in PATHS}
                         for direction in ("original", "candidate")}
        self.units = {direction: {key: self.blobs[f"{direction}-{key:08x}"] for key in CP_KEYS}
                      for direction in ("original", "candidate")}
        self.protected = {key: self.blobs[f"original-{key:08x}"] for key in CP_UNITS if key not in CP_KEYS}
        self.bindings = {"original": dict.fromkeys(AP_KEYS, b"\0"),
                         "candidate": dict(zip(AP_KEYS, (b"\x0a", b"\x0b")))}
        self.states = {"original": self.programs["original"],
                       "cp_only": {"AP": self.programs["original"]["AP"], "CP": self.programs["candidate"]["CP"]},
                       "installed": self.programs["candidate"]}
        for kind, spec in self.audit["programs"].items():
            old, new = self.programs["original"][kind], self.programs["candidate"][kind]
            if (len(old) != spec["bytes"] or len(new) != len(old)
                    or sha(old) != spec["source_sha256"] or sha(new) != spec["candidate_sha256"]):
                raise ValueError("Per-job program integrity differs")
            forward, inverse = bytearray(old), bytearray(new)
            end = 0
            for window in spec["windows"]:
                at, length = window["offset"], window["bytes"]
                before, after = bytes.fromhex(window["before_hex"]), bytes.fromhex(window["after_hex"])
                if (at < end or len(before) != length or len(after) != length
                        or old[at:at+length] != before or new[at:at+length] != after):
                    raise ValueError("Per-job fixed window differs")
                forward[at:at+length] = after; inverse[at:at+length] = before; end = at+length
            if bytes(forward) != new or bytes(inverse) != old:
                raise ValueError("Full program forward/inverse mismatch")


class Session(CheckSession):
    def __init__(self, package, record):
        super().__init__(record, mac_capture=True)
        self.package = package

    def call(self, label, function, *args):
        if not self.healthy:
            raise ValueError("Previous result unknown; all further device commands stopped")
        self.record("device_operation_intent", operation=label)
        self.backend.reset()
        try:
            result = function(*args)
        except BaseException:
            self.healthy = False
            raise
        self.record("device_operation_returned", operation=label)
        return result

    def select_temp(self, name):
        if name not in OWNED:
            raise ValueError("Unowned temporary path")
        status, _ = self.temp_command(15, b"\0/tmp/jiritsu/"+name.encode()+b"\0")
        if status:
            self.healthy = False
            raise ValueError("Temporary selection failed")

    def write_cp(self, key, direction):
        if key not in CP_KEYS or direction not in self.package.units:
            raise ValueError("Unreviewed CP target")
        raw = self.package.units[direction][key]
        if len(raw) != CP_UNITS[key]:
            raise ValueError("CP payload length differs")
        return self.call(f"WRITE41_CP_{key:08x}", self.camera._sendAdjustControlPacket,
                         0x603, 0x41, struct.pack("<II", key, 1)+raw)

    def write_ap(self, key, direction):
        if key not in AP_KEYS or direction not in self.package.bindings:
            raise ValueError("Unreviewed AP target")
        return self.call(f"WRITE2_AP_{key:08x}", self.camera.writeBackup,
                         key, self.package.bindings[direction][key])

    def save_group(self, group):
        if group not in (0x02A4, 0x02CF):
            raise ValueError("Unreviewed save subsystem")
        return self.call(f"SAVE3_{group:04x}", self.camera.saveBackup, group)


def decode_stage(raw, kind, mode, package):
    if mode not in (1, 2) or kind not in ("cp_stage", "ap_stage") or len(raw) != 240:
        raise ValueError("Unknown program stage/mode/ABI")
    v = struct.unpack("<8s4I7q4Q64s64s", raw)
    if v[:3] != (b"A7IRP001", 1, mode):
        raise ValueError("Native program stage ABI/mode differs")
    first, last = ("original", "cp_only") if kind == "cp_stage" else ("cp_only", "installed")
    if mode == 2:
        first, last = last, first
    hashes = lambda state: b"".join(bytes.fromhex(sha(package.states[state][chip])) for chip in PATHS)
    count = len(package.audit["programs"]["CP" if kind == "cp_stage" else "AP"]["windows"])
    ok = (v[3] == 9 and v[4] == count and all(v[i] == 0 for i in range(5, 11))
          and all(v[i] > 0 for i in (11, 12, 13))
          and v[14:16] == tuple(len(package.programs["original"][chip]) for chip in PATHS)
          and v[16] == hashes(first) and v[17] == hashes(last))
    return {"ok": ok, "mode": mode, "phase": v[3], "writes": v[4], "status": v[5],
            "rollback_status": v[6], "readonly_status": v[8], "cleanup_status": v[9]}


def decode_wbi_drop(raw):
    if len(raw) != 192:
        raise ValueError("WBI report length differs")
    v = struct.unpack("<8sII9q16s16s32s32sII", raw)
    if v[:3] != (b"A7WBR001", 1, 1):
        raise ValueError("WBI report ABI/mode differs")
    ok = (all(v[i] == 0 for i in (3, 4, 5, 8, 10, 11)) and v[6] > 0
          and v[7] == v[9] == 1 and v[16:] == (1, 0)
          and v[12].rstrip(b"\0") == b"2\n" and v[13].rstrip(b"\0") == b"0\n"
          and v[14].rstrip(b"\0") == v[15].rstrip(b"\0") == b"*wbi4\n")
    return {"ok": ok, "status": v[3], "drop_write": v[7], "mode_write": v[9],
            "fresh_drop_log": bool(v[16]), "image_mode": v[13].rstrip(b"\0").decode("ascii", "replace")}


def invoke(camera, package, kind, mode, folder, record):
    if kind in ("program_check", "wbi_check") and mode != 0:
        raise ValueError("Check worker cannot be used to install")
    if kind in ("cp_stage", "ap_stage") and mode not in (1, 2):
        raise ValueError("Unknown program transition")
    if kind == "wbi_stage" and mode != 1:
        raise ValueError("Unknown WBI transition")
    if kind not in ("program_check", "wbi_check", "cp_stage", "ap_stage", "wbi_stage"):
        raise ValueError("Unknown native worker")
    wbi = kind.startswith("wbi")
    request = "a7cr.wbi.request" if wbi else "a7cr.install.request"
    result = "a7cr.wbi.result" if wbi else "a7cr.install.result"
    magic = b"A7WBI001" if wbi else b"A7INS001"
    blob = package.blobs[kind]
    expected = {"a7cr.stage.so": blob, "libJit.so": blob, request: struct.pack("<8sII", magic, mode, 0)}
    for name in sorted(OWNED):
        if camera.read_temp(name, True) is not None:
            raise ValueError("Previous native state remains; preserve it and inspect before any invocation")
    camera.check_preload()
    for name in ("a7cr.stage.so", request):
        camera.write_temp(name, expected[name], expected)
        if camera.read_temp(name) != expected[name]:
            raise ValueError("Native staging readback differs")
    record("native_invocation_intent", worker=kind, mode=mode, sha256=sha(blob))
    try:
        camera.write_temp("libJit.so", blob, expected)
        raw = camera.read_temp(result)
        store_private(folder / f"{kind}-mode{mode}.private.bin", raw)
        if kind == "program_check":
            parsed = decode_program(raw, package.audit)
        elif kind == "wbi_check":
            parsed = decode_wbi(raw)
        elif kind == "wbi_stage":
            parsed = decode_wbi_drop(raw)
        else:
            parsed = decode_stage(raw, kind, mode, package)
    except BaseException:
        camera.healthy = False
        raise
    record("native_invocation_returned", worker=kind, mode=mode, report=parsed)
    expected[result] = raw
    for name in ("libJit.so", result, request, "a7cr.stage.so"):
        camera.remove_temp(name, expected)
    record("native_cleanup_verified", worker=kind, mode=mode)
    if not parsed["ok"]:
        raise NativeCheckRejected(f"Native stage did not complete: {kind}: {parsed}")
    return parsed


def preserved(before, after, expected):
    """Compare writable AP settings and four protected CP units.

    Scope follows upstream technical/integration.md and devicesettings.py.
    Full snapshots are retained. Runtime groups (including 02770015) are
    diagnostic observations, never write targets or install gates.
    """
    allowed = {(0, key) for key in AP_KEYS} | {(1, key) for key in CP_KEYS}
    if not set(expected) <= allowed:
        raise ValueError("Expected write is outside this job's settings scope")
    before_diag, after_diag = before[0].get(AP_DIAGNOSTIC), after[0].get(AP_DIAGNOSTIC)
    if before_diag is not None or after_diag is not None:
        if (before_diag is None or after_diag is None or before_diag.attr != after_diag.attr
                or len(before_diag.data) != len(after_diag.data)):
            raise ValueError("Diagnostic AP field layout changed")
    scope = lambda state: [
        {key: value for key, value in state[0].items() if key >> 16 == 0x02CF and key != AP_DIAGNOSTIC},
        {key: state[1][key] for key in CP_UNITS},
    ]
    if any(key not in state[1] for state in (before, after) for key in CP_UNITS):
        raise ValueError("Protected CP unit missing")
    scoped_before, scoped_after = scope(before), scope(after)
    if any(key not in scoped_before[chip] or key not in scoped_after[chip] for chip, key in expected):
        raise ValueError("Expected target is missing")
    count = 0
    for chip in (0, 1):
        if set(scoped_before[chip]) != set(scoped_after[chip]):
            raise ValueError("Protected setting property set changed")
        for key, old in scoped_before[chip].items():
            new = scoped_after[chip][key]
            if (chip, key) in expected:
                if new.data != expected[chip, key] or new.attr != old.attr:
                    raise ValueError(f"Target readback differs: {key:08x}")
            elif (old.data, old.attr) == (new.data, new.attr):
                count += 1
            else:
                raise ValueError(f"Unrelated property changed: chip{chip}/{key:08x}")
    diagnostic = []
    for chip in (0, 1):
        for key in sorted(set(before[chip]) | set(after[chip])):
            if key in scoped_before[chip] or key in scoped_after[chip]:
                continue
            old, new = before[chip].get(key), after[chip].get(key)
            if old is None or new is None or (old.data, old.attr) != (new.data, new.attr):
                diagnostic.append({"chip": chip, "key": f"{key:08x}",
                                   "before_sha256": sha(old.data) if old is not None else None,
                                   "after_sha256": sha(new.data) if new is not None else None})
    return {"preserved_properties": count, "scope": "AP:02cf except 0b6e; CP:unit00,01,02,0d",
            "diagnostic_changes_not_written": diagnostic}


def review_cp_stop(package, state):
    """Validate the complete captured outcome; perform only host file reads."""
    if (state.get("phase") != "STOPPED_INSPECTION_REQUIRED" or state.get("error") != REVIEWED_STOP
            or not state.get("attempt", "").startswith("install-")):
        raise ValueError("This is not the reviewed CP-complete preservation stop")
    folder = (package.root / state["attempt"]).resolve()
    if folder.parent != package.root:
        raise ValueError("Failure evidence escapes this job")
    events_raw = (folder / "events.private.json").read_bytes()
    events = json.loads(events_raw)
    if (events[-1]["phase"] != "stopped_no_retry" or events[-1].get("error") != REVIEWED_STOP
            or not any(e["phase"] == "normal_usb_returned" for e in events)):
        raise ValueError("Failed installation did not end in the reviewed clean USB state")
    intentions = [(e["worker"], e["mode"]) for e in events if e["phase"] == "native_invocation_intent"]
    if intentions != [("wbi_check", 0), ("cp_stage", 1)]:
        raise ValueError("AP/WBI or unexpected native work was already attempted")
    completed = [e["operation"] for e in events if e["phase"] == "device_operation_returned"]
    if (completed.count("SAVE3_02a4") != 1
            or any(op.startswith("WRITE2_AP") or op == "SAVE3_02cf" for op in completed)
            or any(completed.count(f"WRITE41_CP_{key:08x}") != 1 for key in CP_KEYS)):
        raise ValueError("CP save or write outcomes are not fully established")
    byte_reads = {e["chip"]: e for e in events if e["phase"] == "complete_program_byte_readback" and e["tag"] == "after-cp"}
    if (set(byte_reads) != set(PATHS)
            or any(byte_reads[chip]["sha256"] != sha(package.states["cp_only"][chip]) for chip in PATHS)):
        raise ValueError("Complete CP-stage program readback is not established")
    native_raw = (folder / "cp_stage-mode1.private.bin").read_bytes()
    native = decode_stage(native_raw, "cp_stage", 1, package)
    if not native["ok"] or not decode_wbi((folder / "wbi_check-mode0.private.bin").read_bytes())["ok"]:
        raise ValueError("Captured native CP stage did not complete cleanly")
    before, after, files = {}, {}, {"events.private.json": sha(events_raw), "cp_stage-mode1.private.bin": sha(native_raw)}
    preservation = {}
    expected = {(1, key): package.units["candidate"][key] for key in CP_KEYS}
    for source in ("memory", "flash"):
        for table, tag in ((before, "initial"), (after, "after-cp-settings")):
            name = f"{tag}-{source}.private.bin"
            raw = (folder / name).read_bytes(); files[name] = sha(raw)
            sections = backup_sections(raw)
            serial = sections[0][0x00E70003].data
            if len(serial) != 4 or sha(serial.hex().encode("ascii")) != package.binding["ap_serial_sha256"]:
                raise ValueError("Captured settings belong to a different body")
            for key in CP_UNITS:
                wanted = (package.units["candidate"][key] if table is after and key in CP_KEYS
                          else package.units["original"][key] if key in CP_KEYS else package.protected[key])
                if sections[1][key].data != wanted:
                    raise ValueError("Captured CP parameter outcome differs")
            if any(sections[0][key].data != package.bindings["original"][key] for key in AP_KEYS):
                raise ValueError("Captured AP bindings are no longer original")
            table[source] = sections
        preservation[source] = preserved(before[source], after[source], expected)
    report = {"schema": "a7cr-reviewed-cp-stop/1", "failed_attempt": folder.name, "evidence_sha256": files,
              "cp_program_complete": True, "cp_target_units_saved_and_verified": True,
              "ap_program_and_bindings_original": True, "wbi_invalidation_not_attempted": True,
              "normal_usb_exit_verified": True, "native_cp_report": native,
              "preservation": preservation, "camera_current_state_requires_fresh_readback": True,
              "next_operation": "Explicitly re-read cp_only state and saved parameters; finish AP/bindings/WBI only"}
    return report, after


class Job:
    def __init__(self, package, attempt):
        self.package, self.attempt = package, attempt
        self.events = []

    def record(self, phase, **details):
        self.events.append({"phase": phase, "utc": datetime.now(timezone.utc).isoformat(), **details})
        durable_json(self.attempt / "events.private.json", self.events)

    def phase(self, phase, **detail):
        durable_json(self.package.root / "state.private.json", {"phase": phase, "attempt": self.attempt.name,
                                                               "utc": datetime.now(timezone.utc).isoformat(), **detail})
        self.record(phase, **detail)

    def snapshots(self, camera, tag):
        result = {}
        for memory, name in ((True, "memory"), (False, "flash")):
            raw = camera.snapshot(memory)
            store_private(self.attempt / f"{tag}-{name}.private.bin", raw)
            sections = backup_sections(raw)
            serial = sections[0][0x00E70003].data
            if len(serial) != 4 or sha(serial.hex().encode("ascii")) != self.package.binding["ap_serial_sha256"]:
                raise ValueError("AP backup body binding differs")
            for key, original in self.package.protected.items():
                if sections[1][key].data != original:
                    raise ValueError("Protected CP calibration unit changed")
            result[name] = sections
        return result

    def body(self, camera):
        if camera.identity["usb_serial_sha256"] != self.package.binding["usb_serial_sha256"]:
            raise ValueError("Connected USB body differs from the backup")

    def program_state(self, camera, tag, expected=None):
        possible = set(self.package.states)
        for chip, path in PATHS.items():
            raw = camera.read_program(path)
            matching = {state for state, programs in self.package.states.items() if raw == programs[chip]}
            possible &= matching
            if not matching or (expected is not None and raw != self.package.states[expected][chip]):
                store_private(self.attempt / f"{tag}-unexpected-{chip}.private.bin", raw)
                raise ValueError("Complete program readback differs: " + chip)
            self.record("complete_program_byte_readback", tag=tag, chip=chip, bytes=len(raw), sha256=sha(raw))
        if len(possible) != 1:
            raise ValueError("Unsupported AP/CP program combination")
        state = possible.pop()
        self.record("program_state_verified", tag=tag, state=state)
        return state

    def targets(self, snapshots, cp_direction, ap_direction):
        for sections in snapshots.values():
            for key, raw in self.package.units[cp_direction].items():
                if sections[1][key].data != raw:
                    raise ValueError("CP target parameters differ")
            for key, raw in self.package.bindings[ap_direction].items():
                if sections[0][key].data != raw:
                    raise ValueError("AP slot binding differs")

    def known_settings(self, snapshots):
        for sections in snapshots.values():
            for key in CP_KEYS:
                if sections[1][key].data not in (self.package.units["original"][key], self.package.units["candidate"][key]):
                    raise ValueError("CP parameter state is outside this job's original/candidate")
            for key in AP_KEYS:
                if sections[0][key].data not in (self.package.bindings["original"][key], self.package.bindings["candidate"][key]):
                    raise ValueError("AP binding state is outside this job's original/candidate")

    def saveable(self, before, group):
        chip, keys = (1, CP_KEYS) if group == 0x02A4 else (0, AP_KEYS)
        memory, flash = before["memory"][chip], before["flash"][chip]
        for key, value in memory.items():
            if (key >> 16 == group and key not in keys and key != AP_DIAGNOSTIC
                    and (value.data, value.attr) != (flash[key].data, flash[key].attr)):
                raise ValueError("Unrelated unsaved subsystem setting; refusing SAVE3")

    def settings(self, camera, before, group, direction, tag):
        cp = group == 0x02A4
        chip = 1 if cp else 0
        desired = self.package.units[direction] if cp else self.package.bindings[direction]
        # Saving a subsystem must not unexpectedly commit other live settings.
        memory, flash = before["memory"][chip], before["flash"][chip]
        self.saveable(before, group)
        changed = False
        for key, target in desired.items():
            current = camera.required_cp_read(key) if cp else camera.call(f"READ_AP_{key:08x}", camera.camera.readBackup, key)
            if current != memory[key].data:
                raise ValueError("Direct parameter read differs from the fresh snapshot")
            if current != target:
                self.record("parameter_write_intent", key=f"{key:08x}", direction=direction)
                if cp:
                    camera.write_cp(key, direction)
                    got = camera.required_cp_read(key)
                else:
                    camera.write_ap(key, direction)
                    got = camera.call(f"READ_AP_{key:08x}", camera.camera.readBackup, key)
                if got != target:
                    raise ValueError("Parameter write readback differs")
                self.record("parameter_write_readback_verified", key=f"{key:08x}", direction=direction)
                changed = True
            if flash[key].data != target:
                changed = True
        if changed:
            self.record("subsystem_save_intent", subsystem=f"{group:04x}")
            camera.save_group(group)
        after = self.snapshots(camera, tag)
        expected = {(chip, key): value for key, value in desired.items()}
        for name in ("memory", "flash"):
            report = preserved(before[name], after[name], expected)
            self.record("parameter_preservation_verified", source=name, subsystem=f"{group:04x}", **report)
        return after

    def native(self, camera, kind, mode):
        print(f"运行原生阶段：{kind}，模式 {mode}", flush=True)
        return invoke(camera, self.package, kind, mode, self.attempt, self.record)

    def install(self, camera):
        self.body(camera)
        self.program_state(camera, "initial", "original")
        initial = self.snapshots(camera, "initial")
        self.targets(initial, "original", "original")
        self.saveable(initial, 0x02A4); self.saveable(initial, 0x02CF)
        for key in CP_KEYS:
            if camera.required_cp_read(key) != self.package.units["original"][key]:
                raise ValueError("CP pre-write source differs")
        self.native(camera, "wbi_check", 0)
        self.phase("CP_PROGRAM_WRITE_INTENT")
        self.native(camera, "cp_stage", 1)
        self.program_state(camera, "after-cp", "cp_only")
        self.phase("CP_PROGRAM_VERIFIED")
        current = self.settings(camera, initial, 0x02A4, "candidate", "after-cp-settings")
        self.phase("CP_PARAMETERS_SAVED_VERIFIED")
        self.finish_ap(camera, current)

    def complete_ap(self, camera, reviewed_snapshots):
        # No CP native stage, CP writes or SAVE3(02a4) are reachable here.
        self.body(camera)
        self.program_state(camera, "completion-initial", "cp_only")
        current = self.snapshots(camera, "completion-initial")
        self.targets(current, "candidate", "original")
        self.saveable(current, 0x02CF)
        for source in ("memory", "flash"):
            report = preserved(reviewed_snapshots[source], current[source], {})
            self.record("completion_baseline_reverified", source=source, **report)
        for key in CP_KEYS:
            if camera.required_cp_read(key) != self.package.units["candidate"][key]:
                raise ValueError("Previously saved CP parameter no longer matches")
        self.native(camera, "wbi_check", 0)
        self.phase("COMPLETED_CP_STAGE_REVERIFIED_NO_CP_REWRITE")
        self.finish_ap(camera, current)

    def finish_ap(self, camera, current):
        self.native(camera, "ap_stage", 1)
        self.program_state(camera, "after-ap", "installed")
        self.phase("AP_PROGRAM_VERIFIED")
        current = self.settings(camera, current, 0x02CF, "candidate", "after-ap-settings")
        self.targets(current, "candidate", "candidate")
        self.phase("PROGRAMS_AND_SAVED_SETTINGS_VERIFIED")
        self.native(camera, "wbi_stage", 1)
        self.phase("WBI_INVALIDATED_VERIFIED")

    def inspect(self, camera, verify=False):
        self.body(camera)
        state = self.program_state(camera, "inspection", "installed" if verify else None)
        current = self.snapshots(camera, "inspection")
        self.known_settings(current)
        if verify:
            self.targets(current, "candidate", "candidate")
        found = {name: {f"{key:08x}": sha(sections[1][key].data) for key in CP_KEYS}
                 for name, sections in current.items()}
        temporaries = []
        for name in sorted(OWNED):
            raw = camera.read_temp(name, True)
            if raw is not None:
                store_private(self.attempt / (name+".preserved.private.bin"), raw)
                temporaries.append(name)
        self.record("inspection_verified", program_state=state, cp_units=found, preserved_temporary_files=temporaries,
                    loaded_programs_or_photo_behavior_proven=False)
        return state

    def restore(self, camera):
        self.body(camera)
        state = self.program_state(camera, "before-restore")
        current = self.snapshots(camera, "before-restore")
        self.known_settings(current)
        self.saveable(current, 0x02A4); self.saveable(current, 0x02CF)
        if state == "original":
            try:
                self.targets(current, "original", "original")
            except ValueError:
                pass
            else:
                self.record("original_state_verified_no_mutation_needed")
                return False
        self.native(camera, "wbi_check", 0)
        self.phase("RESTORATION_STARTED")
        current = self.settings(camera, current, 0x02CF, "original", "restore-ap-settings")
        if state == "installed":
            self.native(camera, "ap_stage", 2)
            self.program_state(camera, "restore-ap", "cp_only")
            state = "cp_only"
        current = self.settings(camera, current, 0x02A4, "original", "restore-cp-settings")
        if state == "cp_only":
            self.native(camera, "cp_stage", 2)
        self.program_state(camera, "restore-final", "original")
        self.targets(current, "original", "original")
        self.phase("ORIGINAL_PROGRAMS_AND_TARGET_SETTINGS_VERIFIED")
        self.native(camera, "wbi_stage", 1)
        self.phase("RESTORE_WBI_INVALIDATED_VERIFIED")
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "complete-ap", "inspect", "verify", "restore"))
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--battery-percent", type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("Use sudo in your terminal to capture this Mac's camera USB interface")
    if args.command in ("install", "complete-ap", "restore") and (args.battery_percent is None or not 50 <= args.battery_percent <= 100):
        raise ValueError("Enter the camera's actual battery percentage, at least 50")
    os.umask(0o077)
    package = Package(args.workspace)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = package.root / (args.command+"-"+stamp)
    job = Job(package, attempt)
    (ROOT / "private").mkdir(parents=True, exist_ok=True)
    with (ROOT / "private/device.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((package.root / "state.private.json").read_text())
        if args.command == "install" and state["phase"] != "PREPARED_NOT_INSTALLED":
            raise ValueError("This job was already attempted; inspect current state instead of repeating installation")
        if args.command == "verify" and state["phase"] not in ("INSTALLED_PENDING_COLD_START", "FILES_SETTINGS_VERIFIED_PENDING_PHOTOS"):
            raise ValueError("This job has no completed installation to verify")
        if args.command == "complete-ap":
            review, reviewed_snapshots = review_cp_stop(package, state)
        attempt.mkdir(exist_ok=False); private_owner(attempt, True)
        job.record("command_started", command=args.command, battery_percent_user_confirmed=args.battery_percent)
        mutating = args.command in ("install", "complete-ap", "restore")
        try:
            if args.command == "complete-ap":
                durable_json(attempt / "reviewed-previous-cp-stop.private.json", review)
            if mutating:
                job.phase({"install": "INSTALL_ATTEMPT_STARTED", "complete-ap": "AP_COMPLETION_ATTEMPT_STARTED",
                           "restore": "RESTORE_ATTEMPT_STARTED"}[args.command])
            with Session(package, job.record) as camera:
                if args.command == "install":
                    job.install(camera)
                elif args.command == "complete-ap":
                    job.complete_ap(camera, reviewed_snapshots)
                elif args.command == "restore":
                    changed = job.restore(camera)
                else:
                    job.inspect(camera, args.command == "verify")
            if args.command in ("install", "complete-ap"):
                phase = "INSTALLED_PENDING_COLD_START"
            elif args.command == "restore":
                phase = "RESTORED_PENDING_COLD_START" if changed else "ORIGINAL_STATE_VERIFIED_NO_WRITES"
            elif args.command == "verify":
                phase = "FILES_SETTINGS_VERIFIED_PENDING_PHOTOS"
            else:
                phase = None
            if phase:
                job.phase(phase)
            job.record("command_complete", command=args.command, normal_usb_return_confirmed=True)
            print(json.dumps({"phase": phase or "INSPECTION_COMPLETE", "attempt": str(attempt)}, indent=2), flush=True)
            if args.command in ("install", "complete-ap") or (args.command == "restore" and changed):
                print("全部写入和读回已结束。现在可拔 USB、正常关机，等存取灯熄灭后取出电池至少60秒，再装回开机。", flush=True)
                if args.command in ("install", "complete-ap"):
                    print("开机后分别重设 FL2、FL3，检查 Fade=+1；拍摄新的 FL2/FL3/ST 照片并回放，再进行重连核验。", flush=True)
        except BaseException as error:
            if mutating:
                job.phase("STOPPED_INSPECTION_REQUIRED", error_type=type(error).__name__, error=str(error))
            job.record("stopped_no_retry", error_type=type(error).__name__, error=str(error))
            print("已停止，未自动重试。请保留输出和连接，不要重复安装、关机或取电池；先检查当前状态。", file=sys.stderr, flush=True)
            raise


if __name__ == "__main__":
    main()
