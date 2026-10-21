"""Inspect existing six-look fits. No fitting, firmware generation, or device I/O.

All RGB coordinates and response predictions below use the upstream provisional
model. They are not IRE, exposure stops, sensor clipping, or measured A7CR output.
The zero-exposure reference is a diagnostic comparison, not a proposed fix.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "research/repos/a7c2-fl23-research"
sys.path.insert(0, str(UPSTREAM / "src/looks"))
from looktool import calibration, native, project


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    os.umask(0o077)
    folder = ROOT / "private/offline/lut-port/selected-six"
    model_raw = (folder / "shared-appearance-model.private.json").read_bytes()
    model = calibration.validate(json.loads(model_raw), True)
    exposure = model["reference_exposure_stops"]
    axis = np.linspace(0, 1, 10001)
    gray = np.repeat(axis[:, None], 3, axis=1)
    ids, weights = native.interpolation(gray)
    linear_before_clamp = calibration.inverse_st(gray, model) * 2**exposure
    probe_inputs = [.25, .5, .75, .9, .93, .95, .96, .97, 1.]
    indices = np.rint(np.array(probe_inputs)*10000).astype(int)
    audit = json.loads((folder.parent / "candidate/audit.private.json").read_text())
    window = next(w for w in audit["programs"]["CP"]["windows"] if w["offset"] == 0x8000)
    stored_tables = bytes.fromhex(window["after_hex"])[32:]

    def first(mask):
        where = np.flatnonzero(mask)
        return None if len(where) == 0 else float(axis[where[0]])

    rows = []
    for slot in range(1, 7):
        evidence = json.loads((folder / f"slot-{slot}.fit.private.json").read_text())
        raw = (folder / f"slot-{slot}.raw-s8.private.bin").read_bytes()
        profile = ROOT / "research/profiles/originals" / evidence["source_file"]
        if (sha(raw) != evidence["native_table_sha256"]
                or sha(model_raw) != evidence["model_sha256"]
                or sha(profile.read_bytes()) != evidence["source_sha256"]):
            raise ValueError("Preserved fitted inputs changed")
        if stored_tables[(slot-1)*1215:slot*1215] != raw:
            raise ValueError("Analysis table differs from prepared CP patch")
        coefficients = native.decode(raw)
        delta = (coefficients[ids]*weights[:, :, None]).sum(axis=1)/256 @ np.array(model["response_matrix"])
        unbounded = gray + delta
        predicted = native.predict(gray, coefficients, model["response_matrix"])
        references = {}
        for label, stops in (("current", exposure), ("zero_exposure_diagnostic_only", 0)):
            entry = {"source": {"type": "dcp", "path": str(profile), "exposure_stops": stops}}
            render, _ = project.reference(entry, ROOT, model)
            output = render(gray)
            references[label] = {
                "exposure_stops": stops,
                "first_all_channels_white": first(np.all(output >= 1-1e-9, axis=1)),
                "gray_probes": output[indices].round(8).tolist(),
            }
        tail = axis >= 235/255
        row = {
            "slot": slot, "name": evidence["name"],
            "table_sha256": sha(raw), "matches_prepared_CP_table": True,
            "predicted_first_any_channel_white": first(np.any(unbounded >= 1, axis=1)),
            "predicted_first_all_channels_white": first(np.all(unbounded >= 1, axis=1)),
            "gray_probes": predicted[indices].round(8).tolist(),
            "gray_tail_added_rgb": delta[-1].tolist(),
            "gray_tail_added_rgb_max_variation": float(np.ptp(delta[tail], axis=0).max()),
            "references": references,
        }
        rows.append(row)

    settings = json.loads((ROOT / "private/lut-install/six-20261020-01/package.private.json").read_text())["settings"]
    recipes = []
    for slot in range(1, 7):
        fields = [f for f in settings if f["slot"] == slot]
        values = [int.from_bytes(bytes.fromhex(f["after"]), "little", signed=True) for f in fields]
        recipes.append({"slot": slot, "base": values[0],
                        "contrast_highlights_shadows_fade_saturation_sharpness_range_clarity": values[1:]})
    result = {
        "schema": "a7cr-six-highlight-analysis/2", "device_access": False,
        "firmware_or_table_generated": False, "camera_result_measured": False,
        "source_model_sha256": sha(model_raw), "exposure_rendering_stops": exposure,
        "exposure_rendering_multiplier": 2**exposure,
        "first_gray_DCP_input_all_channels_over_one": first(np.all(linear_before_clamp >= 1, axis=1)),
        "model_gray_interpolation_upper_boundary": 235/255,
        "gray_probe_input_encoded_ST": probe_inputs, "rows": rows,
        "recorded_install_recipes_not_current_camera_read": recipes,
        "interpretation_limits": [
            "The response and coordinate model are provisional and were not measured on this A7CR.",
            "Model hard clipping establishes an offline mechanism, not this camera's complete failure cause.",
            "An RGB code value is neither IRE nor a fraction of sensor exposure or dynamic range.",
            "Setting the reference exposure to zero changes midtones as well as highlights; do not apply it as a fix without calibration.",
            "No current photo samples or post-cold-start device read were used.",
        ],
    }
    output = folder / "highlight-analysis-v2.private.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("exposure_rendering_stops", "exposure_rendering_multiplier", "first_gray_DCP_input_all_channels_over_one", "model_gray_interpolation_upper_boundary")}, indent=2))
    for row in rows:
        mid = row["references"]
        print(json.dumps({"name": row["name"], "prepared_table_matches": row["matches_prepared_CP_table"],
            "predicted_white": row["predicted_first_all_channels_white"],
            "tail_delta": np.round(row["gray_tail_added_rgb"], 7).tolist(),
            "tail_delta_variation": row["gray_tail_added_rgb_max_variation"],
            "target_mid_current": mid["current"]["gray_probes"][1],
            "target_mid_zero_exposure": mid["zero_exposure_diagnostic_only"]["gray_probes"][1],
            "target_white_zero_exposure": mid["zero_exposure_diagnostic_only"]["first_all_channels_white"]}, ensure_ascii=False))
    print("Recorded six install recipes:", json.dumps(recipes, ensure_ascii=False))
    print("Saved:", output)


if __name__ == "__main__":
    main()
