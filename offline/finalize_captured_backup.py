"""Verify already captured files after the known redundant CP read stopped.

This performs host file operations only. It preserves the original failed
transport journal and never claims that the USB session exited cleanly.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

from inspect_sources import ROOT

sys.path.insert(0, str(ROOT / "device"))
from read_backup import backup_sections, CP_UNITS


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main(first, second):
    events_path = first / "events.private.json"
    events = json.loads(events_path.read_text())
    if events[-1]["phase"] != "stopped_no_retry":
        raise ValueError("Capture process is not confirmed stopped")
    intents = [event for event in events if event["phase"] == "read_intent"]
    if intents[-1]["operation"] != "CP_READ40_02a40000":
        raise ValueError("This finalizer only covers the reviewed redundant CP-unit read")
    elapsed = (datetime.fromisoformat(events[-1]["utc"])
               - datetime.fromisoformat(intents[-1]["utc"])).total_seconds()
    if not 170 <= elapsed <= 195:
        raise ValueError("The observed stop does not match the reviewed read timeout")
    returned = [event["operation"] for event in events if event["phase"] == "read_returned"]
    if (returned.count("JIRITSU_17") != 2 or returned.count("BACKUP_READ_MEMORY") != 1
            or returned.count("BACKUP_READ_FLASH") != 1):
        raise ValueError("Core program/settings reads are not confirmed returned")
    identities = [event["identity"] for event in events if event["phase"] == "body_identified"]
    if len(identities) != 1 or identities[0]["model"] != "ILCE-7CR":
        raise ValueError("Missing identified A7CR")
    core_names = ("appFw.so", "cpapp-b.bin", "settings-memory.private.bin", "settings-flash.private.bin")
    captured = {}
    files = {}
    for name in core_names:
        raw = (first / name).read_bytes()
        if raw != (second / name).read_bytes():
            raise ValueError("Captured backup copies differ")
        captured[name] = raw
        files[name] = {"bytes": len(raw), "sha256": sha(raw), "origin": "camera_read"}
    memory = backup_sections(captured["settings-memory.private.bin"])
    flash = backup_sections(captured["settings-flash.private.bin"])
    serial = memory[0][0x00E70003].data
    if len(serial) != 4 or serial != flash[0][0x00E70003].data:
        raise ValueError("AP body identity differs between snapshots")
    for key, size in CP_UNITS.items():
        raw = memory[1][key].data
        if len(raw) != size or raw != flash[1][key].data:
            raise ValueError("CP unit size or saved/live data differs")
        name = f"unit-{key:08x}.private.bin"
        for folder in (first, second):
            path = folder / name
            if path.exists():
                if path.read_bytes() != raw:
                    raise ValueError("Existing derived unit differs; preserve it")
            else:
                with path.open("xb") as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                path.chmod(0o600)
            if path.read_bytes() != raw:
                raise ValueError("Derived unit file readback differs")
        files[name] = {"bytes": size, "sha256": sha(raw),
                       "origin": "checksum_valid_memory_snapshot_and_equal_flash_snapshot"}
    report = {
        "schema": "a7cr-captured-backup/1", "phase": "CAPTURED_BACKUP_VERIFIED_TRANSPORT_STOPPED",
        "identity": dict(identities[0], ap_serial_sha256=sha(serial.hex().encode("ascii"))),
        "files": files, "settings_checksum_valid_sections_per_snapshot": 2,
        "calibration_memory_flash_equal": True, "two_local_copies_exact": True,
        "same_volume": first.stat().st_dev == second.stat().st_dev,
        "original_events_sha256": sha(events_path.read_bytes()),
        "transport": {"clean_exit_confirmed": False, "last_request": intents[-1]["operation"],
                      "request_seconds_before_stop": elapsed, "automatic_retry_performed": False},
        "native_worker_uploaded": False, "firmware_or_settings_write_attempted": False,
        "normal_usb_reconnect_verification_required": True,
    }
    encoded = (json.dumps(report, indent=2)+"\n").encode()
    for folder in (first, second):
        path = folder / "captured-backup.private.json"
        if path.exists():
            if path.read_bytes() != encoded:
                raise ValueError("Existing capture manifest differs")
        else:
            with path.open("xb") as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            path.chmod(0o600)
    print(json.dumps({"phase": report["phase"], "files_per_copy": len(files),
                      "total_bytes_per_copy": sum(item["bytes"] for item in files.values()),
                      "two_copies_exact": True, "same_volume": report["same_volume"],
                      "clean_service_exit_confirmed": False}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    main(args.first.resolve(), args.second.resolve())
