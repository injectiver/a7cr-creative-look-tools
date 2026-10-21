"""Exercise per-unit FL23 merges on OFFICIAL DEFAULTS, never on a camera.

Factory example units are not a replacement for a particular body's backup.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import sys

from inspect_sources import ROOT, save_json

sys.path.insert(0, str(ROOT / "research/repos/a7c2-fl23-research/src/fl23/vendor"))
from pmca.backup import BackupFile

CONFIG = ((55, 23, 54, 22), (56, 25, 55, 24))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def factory_units(tag):
    folder = ROOT / "private/components" / tag
    manifest = json.loads((folder / "components.private.json").read_text())
    name = next(item for item in manifest["selected"] if "00_ALLLANG" in item["file"])
    raw = (folder / name["file"]).read_bytes()
    if len(raw) != name["bytes"] or sha(raw) != name["sha256"]:
        raise ValueError("Official factory source changed")
    chunks = []
    for match in re.finditer(b"BK4\0", raw):
        try:
            parsed = BackupFile(io.BytesIO(raw[match.start()-12:]))
            properties = dict(parsed.listProperties())
        except Exception:
            continue
        if 0x02A40001 in properties:
            chunks.append(properties)
    if len(chunks) != 1:
        raise ValueError("Ambiguous CP factory section")
    return {key: chunks[0][key].data for key in (0x02A40000, 0x02A40001, 0x02A40002, 0x02A4000D)}


def donor_records(units):
    records = []
    for target_param, target_bank, source_param, source_bank in CONFIG:
        if units[0x02A40001][0x1200+source_param] != source_bank:
            raise ValueError("Donor chroma selector differs")
        if units[0x02A4000D][0x196+source_param] != source_bank:
            raise ValueError("Donor matrix selector differs")
        records.append({"parameter": target_param, "bank": target_bank,
                        "chroma": units[0x02A40001][0x1250+source_bank*64:0x1250+source_bank*64+64],
                        "matrix": units[0x02A4000D][0x1E0+source_bank*768:0x1E0+source_bank*768+576]})
    return records


def merge(unit01, unit0d, records):
    if len(unit01) != 8192 or len(unit0d) != 28672:
        raise ValueError("Unexpected target unit sizes")
    first, second = bytearray(unit01), bytearray(unit0d)
    for record in records:
        parameter, bank = record["parameter"], record["bank"]
        if (parameter, bank) not in {(55, 23), (56, 25)}:
            raise ValueError("Out-of-scope FL23 target")
        chroma, matrix = record["chroma"], record["matrix"]
        if len(chroma) != 64 or len(matrix) != 576:
            raise ValueError("Unexpected native record sizes")
        if unit01[0x1200+parameter] or unit0d[0x196+parameter]:
            raise ValueError("Target parameter is occupied")
        if bank in unit01[0x1200:0x1250] or bank in unit0d[0x196:0x196+74]:
            raise ValueError("Target bank is already referenced")
        c, m = 0x1250+bank*64, 0x1E0+bank*768
        if any(unit01[c:c+64]) or any(unit0d[m:m+576]):
            raise ValueError("Target bank contains data")
        first[0x1200+parameter] = bank
        second[0x196+parameter] = bank
        first[c:c+64] = chroma
        second[m:m+576] = matrix
    return bytes(first), bytes(second)


def main():
    original = factory_units("ILCE-7CR_2.01")
    donor = factory_units("ILCE-1M2_4.00")
    records = donor_records(donor)
    before = (original[0x02A40001], original[0x02A4000D])
    after = merge(*before, records)
    # Realistic non-target values must survive a fresh body-specific merge.
    altered = bytearray(before[0]); altered[0x1250] ^= 0x01
    preserved, _ = merge(bytes(altered), before[1], records)
    assert preserved[0x1250] == altered[0x1250]
    rejected = 0
    for occupied_offset in (0x1200+55, 0x1250+23*64):
        occupied = bytearray(before[0]); occupied[occupied_offset] = 1
        try:
            merge(bytes(occupied), before[1], records)
        except ValueError:
            rejected += 1
        else:
            raise ValueError("An occupied parameter/bank was accepted")
    allowed01 = {0x1200+p for p, _, _, _ in CONFIG}
    allowed0d = {0x196+p for p, _, _, _ in CONFIG}
    for _, bank, _, _ in CONFIG:
        allowed01.update(range(0x1250+bank*64, 0x1250+bank*64+64))
        allowed0d.update(range(0x1E0+bank*768, 0x1E0+bank*768+576))
    summary = []
    for key, old, new, allowed in zip((0x02A40001, 0x02A4000D), before, after, (allowed01, allowed0d)):
        changed = {at for at, (a, b) in enumerate(zip(old, new)) if a != b}
        if not changed <= allowed or len(old) != len(new):
            raise ValueError("Unrelated unit bytes changed")
        reverted = bytearray(new)
        for at in allowed:
            reverted[at] = old[at]
        if bytes(reverted) != old:
            raise ValueError("Unit inverse differs")
        summary.append({"key": f"0x{key:08x}", "bytes": len(new),
                        "source_sha256": sha(old), "example_sha256": sha(new),
                        "actual_changed_bytes": len(changed), "inverse_roundtrip_exact": True})
    report = {"schema": "a7cr-fl23-color-plan/1", "device_access": False,
              "factory_example_only": True, "body_backup_required": True,
              "existing_non_target_bytes_preserved": True,
              "occupied_source_rejections": rejected, "units": summary,
              "records": [{key: (value.hex() if isinstance(value, bytes) else value)
                           for key, value in record.items()} for record in records],
              "ap_binding_migration": {"0x02cf1287": "0a", "0x02cf1289": "0b"}}
    save_json(ROOT / "private/offline/fl23-candidate/color-plan.private.json", report)
    print(json.dumps({key: value for key, value in report.items() if key != "records"}, indent=2))


if __name__ == "__main__":
    main()
