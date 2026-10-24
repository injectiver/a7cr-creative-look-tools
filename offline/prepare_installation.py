"""Prepare a private, body-specific local installation job. Never opens USB."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

from inspect_sources import ROOT, save_json
from color_plan import merge, donor_records, factory_units

sys.path.insert(0, str(ROOT / "device"))
from read_backup import backup_sections, CP_UNITS
from preflight_fl23 import decode_program, decode_wbi
from fl23_install import Package, durable_json, store_private, preserved, CP_KEYS, AP_KEYS

CAPTURE = ROOT / "private/body-backups/baseline"
SECOND = ROOT / "private/body-backup-copy/baseline"
PREFLIGHT = ROOT / "private/preflight/fl23"
DESTINATION = ROOT / "private/install/fl23"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_completed_capture(first, second):
    """Use this run's successful backup, not the historical failure finalizer."""
    raw = (first / "backup.private.json").read_bytes()
    if raw != (second / "backup.private.json").read_bytes():
        raise ValueError("Backup manifests differ between the two copies")
    captured = json.loads(raw)
    if (captured.get("schema") != "a7cr-read-only-backup/1"
            or captured.get("phase") != "READ_ONLY_BACKUP_COMPLETE"
            or captured.get("firmware_version_user_confirmed") != "2.01"
            or captured.get("identity", {}).get("model") != "ILCE-7CR"
            or captured.get("camera_files_or_settings_written") is not False
            or captured.get("native_worker_uploaded") is not False):
        raise ValueError("A complete unchanged A7CR 2.01 backup is required")
    events = json.loads((first / "events.private.json").read_text())
    phases = [event["phase"] for event in events]
    if (not phases or phases[-1] != "complete" or "stopped_no_retry" in phases
            or "service_exit_returned" not in phases or "normal_usb_returned" not in phases):
        raise ValueError("Backup service exit and normal USB return are not confirmed")
    return captured


def prepare():
    os.umask(0o077)
    audit = json.loads((ROOT / "private/offline/fl23-candidate/audit.private.json").read_text())
    workers_path = ROOT / "private/native-workers/workers.private.json"
    workers = json.loads(workers_path.read_text())
    captured = load_completed_capture(CAPTURE, SECOND)
    preflight = json.loads((PREFLIGHT / "preflight.private.json").read_text())
    events = json.loads((PREFLIGHT / "events.private.json").read_text())
    if (preflight["phase"] != "CAMERA_CHECKS_PASSED_NOT_INSTALLED" or events[-1]["phase"] != "complete"
            or any(e["phase"] == "stopped_no_retry" for e in events)
            or not any(e["phase"] == "normal_usb_returned" for e in events)
            or preflight["firmware_or_settings_written"] or preflight["wbi_modified"]):
        raise ValueError("Check-only camera job has not completed cleanly")
    if (not workers["native_simulation_passed"] or workers["synthetic_case_count"] < 14
            or workers["body_binding"] != captured["identity"]
            or preflight["body_identity"]["usb_serial_sha256"] != captured["identity"]["usb_serial_sha256"]):
        raise ValueError("Worker simulation/body binding differs")
    for kind, decoder in (("program_check", lambda raw: decode_program(raw, audit)), ("wbi_check", decode_wbi)):
        report = decoder((PREFLIGHT / (kind+".result.private.bin")).read_bytes())
        intents = [e for e in events if e["phase"] == "native_check_invocation_intent" and e["worker"] == kind]
        if (not report["ok"] or len(intents) != 1 or intents[0]["mode"] != 0
                or intents[0]["sha256"] != workers["workers"][kind]["sha256"]):
            raise ValueError("Native preflight evidence differs")
    payloads = {}
    for name, spec in captured["files"].items():
        raw = (CAPTURE / name).read_bytes()
        if len(raw) != spec["bytes"] or sha(raw) != spec["sha256"] or raw != (SECOND / name).read_bytes():
            raise ValueError("Body backup copies differ: " + name)
    original_sections = backup_sections((CAPTURE / "settings-memory.private.bin").read_bytes())
    snapshots = {}
    for tag in ("memory-before", "flash-before", "memory-after", "flash-after"):
        raw = (PREFLIGHT / (tag+".private.bin")).read_bytes()
        sections = backup_sections(raw)
        serial = sections[0][0x00E70003].data
        if (len(serial) != 4 or sha(serial.hex().encode("ascii")) != captured["identity"]["ap_serial_sha256"]
                or any(sections[1][key].data != original_sections[1][key].data for key in CP_UNITS)
                or any(sections[0][key].data != b"\0" for key in AP_KEYS)):
            raise ValueError("Fresh preflight parameters/body differ from the captured sources")
        snapshots[tag] = sections
    for source in ("memory", "flash"):
        preserved(snapshots[source+"-before"], snapshots[source+"-after"], {})
    for key in CP_KEYS:
        read_events = [e for e in events if e["phase"] == "required_cp_read_verified" and e["key"] == f"{key:08x}"]
        if len(read_events) != 1 or read_events[0]["sha256"] != sha(original_sections[1][key].data):
            raise ValueError("Required interchip read was not verified against this body")
    for kind, spec in audit["programs"].items():
        old = (CAPTURE / spec["file"]).read_bytes()
        new = (ROOT / "private/offline/fl23-candidate" / spec["file"]).read_bytes()
        if sha(old) != spec["source_sha256"] or sha(new) != spec["candidate_sha256"]:
            raise ValueError("Body program/candidate differs")
        payloads["original-"+kind] = old
        payloads["candidate-"+kind] = new
    for key in CP_UNITS:
        payloads[f"original-{key:08x}"] = original_sections[1][key].data
    new_units = merge(*(payloads[f"original-{key:08x}"] for key in CP_KEYS), donor_records(factory_units("ILCE-1M2_4.00")))
    for key, raw in zip(CP_KEYS, new_units):
        prepared = ROOT / "private/offline/baseline-body-plan" / f"candidate-unit-{key:08x}.private.bin"
        if raw != prepared.read_bytes():
            raise ValueError("Body color merge differs from the reviewed plan")
        payloads[f"candidate-{key:08x}"] = raw
    for kind in ("program_check", "cp_stage", "ap_stage", "wbi_check", "wbi_stage"):
        spec = workers["workers"][kind]
        raw = (ROOT / spec["file"]).read_bytes()
        if len(raw) != spec["bytes"] or sha(raw) != spec["sha256"]:
            raise ValueError("Native worker changed")
        payloads[kind] = raw
    if shutil.disk_usage(ROOT).free < sum(map(len, payloads.values()))+256*1024*1024:
        raise ValueError("Insufficient free space for a private job and failure evidence")
    DESTINATION.parent.mkdir(mode=0o700, exist_ok=True)
    DESTINATION.mkdir(mode=0o700, exist_ok=False)
    (DESTINATION / "payload").mkdir(mode=0o700)
    files = {}
    for name, raw in payloads.items():
        path = DESTINATION / "payload" / (name+".private.bin")
        store_private(path, raw)
        if path.read_bytes() != raw:
            raise ValueError("Prepared payload readback differs")
        files[name] = {"file": str(path.relative_to(DESTINATION)), "bytes": len(raw), "sha256": sha(raw)}
    license_path = ROOT / "research/repos/a7c2-fl23-research/src/fl23/LICENSE"
    store_private(DESTINATION / "UPSTREAM-MIT-LICENSE.txt", license_path.read_bytes())
    for name in ("preflight.private.json", "events.private.json", "program_check.result.private.bin", "wbi_check.result.private.bin"):
        store_private(DESTINATION / ("preflight-"+name), (PREFLIGHT / name).read_bytes())
    package = {"schema": "a7cr-fl23-local-installation/1", "model": "ILCE-7CR", "version": "2.01",
               "body_binding": captured["identity"], "audit": audit, "files": files,
               "sources": {"first_backup": str(CAPTURE), "second_backup": str(SECOND), "camera_preflight": str(PREFLIGHT)},
               "native_simulation_cases": workers["synthetic_case_count"], "camera_preflight_passed": True,
               "physical_installation_started": False, "is_sony_signed_update": False,
               "install_order": ["CP program", "CP unit01/unit0d + SAVE3(02a4)", "AP program", "AP bindings + SAVE3(02cf)", "WBI drop1 -> mode0"],
               "restore_scope": "Known original/cp_only/installed file states and original/candidate target parameters; service access and WBI mode2 required. No brick/power-loss recovery guarantee.",
               "photo_lut_port_included": False}
    durable_json(DESTINATION / "package.private.json", package)
    Package(DESTINATION)
    durable_json(DESTINATION / "state.private.json", {"phase": "PREPARED_NOT_INSTALLED"})
    workers["camera_preflight_passed"] = True
    workers["camera_preflight_job"] = str(PREFLIGHT.relative_to(ROOT))
    save_json(workers_path, workers)
    print(json.dumps({"phase": "PREPARED_NOT_INSTALLED", "workspace": str(DESTINATION),
                      "camera_preflight_verified": True, "payload_bytes": sum(map(len, payloads.values())),
                      "device_access_performed_by_this_script": False, "photo_lut_port_included": False}, indent=2))


if __name__ == "__main__":
    prepare()
