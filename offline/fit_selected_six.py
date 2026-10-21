"""Fit the user's six selected DCP look/tone stages. No camera operations.

The unchanged upstream A7C II shared appearance/ISP model is used as an
explicit experimental starting point; this is not measured A7CR calibration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time

from inspect_sources import ROOT, save_json

UPSTREAM = ROOT / "research/repos/a7c2-fl23-research"
sys.path.insert(0, str(UPSTREAM / "src/looks"))
from looktool import calibration, native, project

SELECTED = (
    ("Classic Negative", "Classic Neg.", "Fuji-MTriton"),
    ("Classic Chrome", "Classic Chrome", "Fuji-MTriton"),
    ("Nostalgic Negative", "Nostalgic Neg.", "Fuji-MTriton"),
    ("Eterna", "Eterna", "Fuji-MTriton"),
    ("Positive Film", "GR Positive Film", "Ricoh-GRIII"),
    ("Negative Film", "GR Negative Film", "Ricoh-GRIII"),
)
OUT = ROOT / "private/offline/lut-port/selected-six"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    os.umask(0o077)
    OUT.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((ROOT / "private/offline/lut-port/profile-catalog.private.json").read_text())
    model_path = UPSTREAM / "src/looks/assets/rendering-model-v1.json"
    model_raw = model_path.read_bytes()
    model = calibration.validate(json.loads(model_raw), True)
    stored_model = OUT / "shared-appearance-model.private.json"
    if stored_model.exists() and stored_model.read_bytes() != model_raw:
        raise ValueError("Retain the prior model; prepared appearance model has changed")
    stored_model.write_bytes(model_raw)
    rows = []
    for slot, (query, name, family) in enumerate(SELECTED, 1):
        matches = [item for item in catalog["originals"] if item["file"].startswith(family+"/")
                   and query in item["profile_name"]]
        if len(matches) != 1:
            raise ValueError("Selected profile is not unique: " + name)
        source = matches[0]
        path = ROOT / "research/profiles/originals" / source["file"]
        if sha(path.read_bytes()) != source["sha256"]:
            raise ValueError("Original DCP changed")
        table, evidence = OUT / f"slot-{slot}.raw-s8.private.bin", OUT / f"slot-{slot}.fit.private.json"
        if table.exists() and evidence.exists():
            row = json.loads(evidence.read_text())
            if (row["source_sha256"] != source["sha256"] or row["model_sha256"] != sha(model_raw)
                    or row["native_table_sha256"] != sha(table.read_bytes())):
                raise ValueError("Existing fitted result differs; preserve it")
            native.decode(table.read_bytes())
            rows.append(row)
            print(f"槽 {slot}：已核对既有拟合 {name}", flush=True)
            continue
        if table.exists() or evidence.exists():
            raise ValueError("A partial fit already exists; inspect before repeating")
        entry = {"slot": slot, "name": name, "base": "ST", "source": {
            "type": "dcp", "path": str(path), "exposure_stops": model.get("reference_exposure_stops", 0),
            "attribution": source["embedded_copyright"]}}
        render, inventory = project.reference(entry, ROOT, model)
        print(f"槽 {slot}：电脑端拟合 {name}，不连接相机", flush=True)
        started = time.monotonic()
        raw, fit = native.fit_reference(render, model["response_matrix"], seed=201+slot)
        if len(raw) != 1215 or not fit["convergence"]["converged"]:
            raise ValueError("Native table fit did not pass shape/convergence checks")
        native.decode(raw)
        row = {"slot": slot, "name": name, "required_base": "ST", "source_file": source["file"],
               "source_sha256": source["sha256"], "model_sha256": sha(model_raw),
               "native_table_sha256": sha(raw), "bytes": len(raw), "source_inventory": inventory,
               "attribution": source["embedded_copyright"], "fit": fit,
               "elapsed_seconds": time.monotonic()-started, "measured_a7cr_calibration": False,
               "camera_installed": False}
        table.write_bytes(raw); save_json(evidence, row)
        rows.append(row)
        print(json.dumps({"slot": slot, "name": name, "bytes": len(raw),
                          "synthetic_rgb_mae": fit["synthetic_holdout"]["rgb_mae"],
                          "a7cr_camera_accuracy_verified": False}, ensure_ascii=False), flush=True)
    save_json(OUT / "selected-six.private.json", {
        "schema": "a7cr-selected-six-fits/1", "slots": rows, "device_access": False,
        "source_model": "Shared provisional A7C II single-scene bridge; user selected reuse as initial experiment",
        "a7cr_color_accuracy_verified": False, "installation_adapter_ready": False,
        "original_looks_to_preserve": ["ST", "FL", "FL2", "FL3"],
    })
    print(json.dumps({"selected_profiles_fitted": len(rows), "native_table_bytes": sum(row["bytes"] for row in rows),
                      "device_access": False, "installation_adapter_ready": False}, indent=2), flush=True)


if __name__ == "__main__":
    main()
