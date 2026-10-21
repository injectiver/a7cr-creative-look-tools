"""Analyze captured A7CR files without opening USB or changing the capture job."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from inspect_sources import ROOT, save_json
from color_plan import factory_units, donor_records, merge

sys.path.insert(0, str(ROOT / "device"))
from read_backup import backup_sections


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def analyze(job, second):
    audit = json.loads((ROOT / "private/offline/fl23-candidate/audit.private.json").read_text())
    events = json.loads((job / "events.private.json").read_text())
    identified = [event["identity"] for event in events if event["phase"] == "body_identified"]
    if len(identified) != 1 or identified[0]["model"] != "ILCE-7CR":
        raise ValueError("Missing unambiguous live A7CR identity")
    programs = {}
    for kind, spec in audit["programs"].items():
        raw = (job / spec["file"]).read_bytes()
        if raw != (second / spec["file"]).read_bytes():
            raise ValueError("Program backup copies differ")
        if len(raw) != spec["bytes"] or sha(raw) != spec["source_sha256"]:
            raise ValueError("Captured stock program differs from the reviewed offline input")
        candidate = (ROOT / "private/offline/fl23-candidate" / spec["file"]).read_bytes()
        if sha(candidate) != spec["candidate_sha256"]:
            raise ValueError("Reviewed offline candidate changed")
        programs[kind] = {"file": spec["file"], "source_sha256": sha(raw),
                          "candidate_sha256": sha(candidate), "second_copy_exact": True,
                          "reviewed_official_source_exact": True}
    snapshots = {}
    for key, name in (("memory", "settings-memory.private.bin"), ("flash", "settings-flash.private.bin")):
        raw = (job / name).read_bytes()
        if raw != (second / name).read_bytes():
            raise ValueError("Settings backup copies differ")
        snapshots[key] = backup_sections(raw)
    serials = [sections[0][0x00E70003].data for sections in snapshots.values()]
    if len(serials[0]) != 4 or serials[0] != serials[1]:
        raise ValueError("Saved/live AP body identity differs")
    keys = (0x02A40000, 0x02A40001, 0x02A40002, 0x02A4000D)
    units = {key: snapshots["memory"][1][key].data for key in keys}
    if any(units[key] != snapshots["flash"][1][key].data for key in keys):
        raise ValueError("Memory/flash CP calibration units differ")
    records = donor_records(factory_units("ILCE-1M2_4.00"))
    first, second_unit = merge(units[0x02A40001], units[0x02A4000D], records)
    out = ROOT / "private/offline" / (job.name+"-body-plan")
    out.mkdir(parents=True, exist_ok=True)
    for key, raw in units.items():
        (out / f"captured-unit-{key:08x}.private.bin").write_bytes(raw)
    for key, raw in ((0x02A40001, first), (0x02A4000D, second_unit)):
        (out / f"candidate-unit-{key:08x}.private.bin").write_bytes(raw)
    bindings = {}
    for key, target in ((0x02CF1287, b"\x0a"), (0x02CF1289, b"\x0b")):
        current, saved = (snapshots[source][0][key].data for source in ("memory", "flash"))
        if len(current) != 1 or current != saved or current != b"\0":
            raise ValueError("Reserved look binding is not the expected untouched ST binding")
        bindings[f"0x{key:08x}"] = {"memory_before": current.hex(), "flash_before": saved.hex(),
                                    "target": target.hex()}
    report = {"schema": "a7cr-body-specific-plan/1", "device_access": False,
              "capture_job": job.name, "source_programs_verified": programs,
              "body_binding": dict(identified[0], ap_serial_sha256=sha(serials[0].hex().encode("ascii"))),
              "memory_flash_calibration_equal": True,
              "captured_cp_units": {f"0x{key:08x}": {"bytes": len(raw), "sha256": sha(raw)}
                                    for key, raw in units.items()},
              "candidate_color_units": {f"0x{key:08x}": {"bytes": len(new), "sha256": sha(new),
                                           "changed_bytes": sum(a != b for a, b in zip(units[key], new))}
                                        for key, new in ((0x02A40001, first), (0x02A4000D, second_unit))},
              "ap_binding_plan": bindings,
              "capture_last_phase": events[-1]["phase"],
              "service_exit_confirmed": any(event["phase"] == "normal_usb_returned" for event in events),
              "installable_package": False, "firmware_or_settings_write_performed": False,
              "note": "Captured snapshots contain checksum-verified AP/CP sections. Transport completion is tracked separately."}
    save_json(out / "body-plan.private.json", report)
    print(json.dumps({key: report[key] for key in ("capture_job", "memory_flash_calibration_equal",
                      "candidate_color_units", "ap_binding_plan", "capture_last_phase", "service_exit_confirmed",
                      "installable_package")}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job", type=Path)
    parser.add_argument("second_copy", type=Path)
    args = parser.parse_args()
    analyze(args.job.resolve(), args.second_copy.resolve())
