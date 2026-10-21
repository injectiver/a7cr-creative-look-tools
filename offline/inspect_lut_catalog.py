"""Inspect original DCP references and A7CR port boundaries, without USB.

Retain profile bytes/attribution. This does not fit A7CR colors, create a
camera installer, or bypass the A7C II importer's source/model guards.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import zipfile

from inspect_sources import ROOT, save_json

UPSTREAM = ROOT / "research/repos/a7c2-fl23-research"
sys.path.insert(0, str(UPSTREAM / "src/looks"))
from looktool.references import DcpLook
from looktool import device_layout

OUT = ROOT / "private/offline/lut-port"
ARCHIVE = ROOT / "research/profiles/a7c2-dcp-profiles-2026-10-18.zip"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def profiles():
    pending = ARCHIVE.with_suffix(ARCHIVE.suffix+".part")
    if not ARCHIVE.exists():
        if not zipfile.is_zipfile(pending):
            raise ValueError("Original profile archive is not complete")
        pending.rename(ARCHIVE)
    manifest = json.loads((UPSTREAM / "docs/profiles/manifest.json").read_text())
    destination = ROOT / "research/profiles/originals"
    destination.mkdir(parents=True, exist_ok=True)
    result = []
    with zipfile.ZipFile(ARCHIVE) as source:
        members = source.infolist()
        if sum(item.file_size for item in members) > 32*1024*1024:
            raise ValueError("Unexpected profile archive size")
        for item in members:
            relative = PurePosixPath(item.filename)
            if (relative.is_absolute() or ".." in relative.parts or "\\" in item.filename
                    or (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("Unsafe archive path/type")
            if item.is_dir():
                continue
            if relative.parts[0] != "a7c2-dcp-profiles":
                raise ValueError("Unexpected archive root")
            path = destination.joinpath(*relative.parts[1:])
            raw = source.read(item)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if path.read_bytes() != raw:
                    raise ValueError("Existing original profile/notice differs")
            else:
                path.write_bytes(raw)
        for item in manifest["profiles"]:
            path = destination / item["file"]
            raw = path.read_bytes()
            if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
                raise ValueError("Profile differs from the upstream original-byte inventory")
            parsed = DcpLook(path)
            result.append({"file": item["file"], "profile_name": item["profile_name"],
                           "source_camera": item["camera_model"], "sha256": item["sha256"], "bytes": len(raw),
                           "embedded_copyright": item["embedded_copyright"], "license_note": item["license_note"],
                           "original_bytes_verified": True, "look_inventory": parsed.inventory()})
    if len(result) != 18:
        raise ValueError("Expected all 18 original profiles")
    report = {"schema": "a7cr-lut-reference-inventory/1", "archive_sha256": sha(ARCHIVE.read_bytes()),
              "originals": result, "profile_count": len(result), "device_access": False,
              "upstream_target": "ILCE-7CM2", "requested_target": "ILCE-7CR",
              "a7cr_color_calibration_verified": False, "converted_or_installed_on_camera": False,
              "note": "Only source look/tone data was parsed; camera calibration matrices were not transplanted."}
    save_json(OUT / "profile-catalog.private.json", report)
    return report


def audit():
    asset = json.loads((UPSTREAM / "src/looks/assets/runtime-v1.json").read_text())
    folder = ROOT / "private/install/20261020-a7cr-fl23-01/payload"
    ap, cp = ((folder / f"candidate-{kind}.private.bin").read_bytes() for kind in ("AP", "CP"))
    result = []
    for kind, data, spec, field, raw_key in (
        ("AP", ap, next(s for s in asset["ap_sources"] if s["kind"] == "fl23"), "restore", "hex"),
        ("CP", cp, next(s for s in asset["cp_sources"] if s["kind"] == "fl23"), "windows", "before"),
    ):
        rows = []
        for window in spec[field]:
            raw = bytes.fromhex(window[raw_key]); offsets = []
            if any(raw) and len(raw) >= 12:
                at = data.find(raw)
                while at >= 0 and len(offsets) < 3:
                    offsets.append(at); at = data.find(raw, at+1)
            rows.append({"upstream_offset": hex(window["offset"]), "bytes": len(raw),
                         "zero_filled_ownership_unproven": not any(raw),
                         "unique_matching_a7cr_offset": hex(offsets[0]) if len(offsets) == 1 else None,
                         "matches_capped_at3": len(offsets) if any(raw) and len(raw) >= 12 else None})
        result.append({"component": kind, "a7cr_candidate_sha256": sha(data),
                       "upstream_exact_source_sha256": spec["sha256"],
                       "source_identity_matches": sha(data) == spec["sha256"], "source_windows": rows})
    try:
        device_layout.identify(ap, cp)
    except ValueError as error:
        refusal = str(error)
    else:
        raise ValueError("Unexpected acceptance of unported A7CR programs by the A7C II adapter")
    report = {"schema": "a7cr-custom-lut-port-audit/1", "device_access": False, "installable": False,
              "upstream_model": "ILCE-7CM2", "target_model": "ILCE-7CR", "components": result,
              "unmodified_upstream_refusal": refusal,
              "remaining": ["A7CR AP title/converter and selected-slot descriptors",
                            "CP hooks/branches and preview table packing/upload",
                            "Storage loading, ownership, references and BSS boundaries",
                            "A7CR language-resource structure and selected titles",
                            "A7CR color bridge assessment",
                            "Fresh body checkpoint, install/inverse/readback and runtime/physical verification"]}
    save_json(OUT / "source-window-audit.private.json", report)
    return report


def main():
    os.umask(0o077)
    OUT.mkdir(parents=True, exist_ok=True)
    catalog, port = profiles(), audit()
    print(json.dumps({"profiles_verified_and_parsed": catalog["profile_count"],
                      "a7cr_color_calibration_verified": False,
                      "unmodified_upstream_refuses_a7cr": port["unmodified_upstream_refusal"],
                      "device_access": False, "installable": False}, indent=2))


if __name__ == "__main__":
    main()
