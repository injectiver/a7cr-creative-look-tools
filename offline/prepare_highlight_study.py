"""Prepare non-installable white-anchor diagnostic tables from preserved fits.

Only a neutral node in the highest luminance plane may change. A provisional
prediction can test this small change without claiming measured A7CR behavior.
No firmware, installation package, camera settings, or device I/O is produced.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/repos/a7c2-fl23-research/src/looks"))
from looktool import native

SOURCE = ROOT / "private/offline/lut-port/selected-six"
OUT = ROOT / "private/offline/highlight-study/white-anchor-v1"
NODE = 4*81 + 4*9 + 4


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def preserve(path, raw):
    if path.exists() and path.read_bytes() != raw:
        raise ValueError("Keep the previous study; refusing to replace different data")
    if not path.exists():
        path.write_bytes(raw)


def unbounded(rgb, coefficients, response):
    ids, weights = native.interpolation(rgb)
    delta = (coefficients[ids]*weights[:, :, None]).sum(axis=1)/256
    return rgb + delta @ response


def main():
    os.umask(0o077)
    OUT.mkdir(parents=True, exist_ok=True)
    model_raw = (SOURCE / "shared-appearance-model.private.json").read_bytes()
    model = json.loads(model_raw)
    response = native.validate_response(model["response_matrix"])
    axis = np.linspace(0, 1, 10001)
    gray = np.repeat(axis[:, None], 3, axis=1)
    colors = np.random.default_rng(20261020).uniform(0, 1, (50000, 3))
    unchanged_domain = native.coordinates(colors)[:, 0] <= .75
    probes = [.25, .5, .7, .75, .9, .95, .97, .99, 1.]
    probe_ids = np.rint(np.array(probes)*10000).astype(int)
    luma = np.array([.299, .587, .114])
    rows = []
    for slot in range(1, 7):
        evidence = json.loads((SOURCE / f"slot-{slot}.fit.private.json").read_text())
        old_raw = (SOURCE / f"slot-{slot}.raw-s8.private.bin").read_bytes()
        if sha(old_raw) != evidence["native_table_sha256"] or sha(model_raw) != evidence["model_sha256"]:
            raise ValueError("Preserved source differs")
        old = native.decode(old_raw)
        old_gray_raw = unbounded(gray, old, response)
        early_gray_white = np.any(np.all(old_gray_raw[:-1] >= 1, axis=1))
        new = old.copy()
        if early_gray_white:
            new[NODE] = 0
        new_raw = native.encode(new)
        new = native.decode(new_raw)
        allowed_offsets = {NODE, 405+NODE, 810+NODE}
        changed = [i for i, (a, b) in enumerate(zip(old_raw, new_raw)) if a != b]
        if not set(changed) <= allowed_offsets:
            raise ValueError("Study changed a non-anchor coefficient")
        old_gray = native.predict(gray, old, response)
        new_gray_raw = unbounded(gray, new, response)
        new_gray = native.predict(gray, new, response)
        before_color = native.predict(colors, old, response)
        after_color = native.predict(colors, new, response)
        unchanged_error = float(np.abs(before_color[unchanged_domain]-after_color[unchanged_domain]).max())
        if unchanged_error > 1e-12 or not np.array_equal(old_gray[5000], new_gray[5000]):
            raise ValueError("Study changed the lower luminance domain or midgray")
        if np.any(new_gray_raw[:-1] >= 1):
            raise ValueError("Early neutral channel clipping remains in the provisional prediction")
        if np.diff(new_gray @ luma).min() < -1e-10:
            raise ValueError("Non-monotone neutral response")
        name = f"slot-{slot}.experimental.raw-s8.bin"
        preserve(OUT / name, new_raw)
        row = {
            "slot": slot, "name": evidence["name"], "changed": bool(changed),
            "source_sha256": sha(old_raw), "experimental_sha256": sha(new_raw),
            "file": name, "bytes": len(new_raw), "changed_byte_offsets": changed,
            "original_anchor_coefficients": old[NODE].tolist(),
            "experimental_anchor_coefficients": new[NODE].tolist(),
            "predicted_early_neutral_white_removed": True,
            "midgray_unchanged": True,
            "unchanged_domain_random_samples": int(np.count_nonzero(unchanged_domain)),
            "unchanged_domain_max_abs_difference": unchanged_error,
            "neutral_min_luma_step": float(np.diff(new_gray @ luma).min()),
            "random_RGB_max_abs_difference": float(np.abs(after_color-before_color).max()),
            "gray_probe_before": old_gray[probe_ids].round(8).tolist(),
            "gray_probe_experimental": new_gray[probe_ids].round(8).tolist(),
        }
        rows.append(row)
        print(json.dumps({"slot": slot, "name": row["name"], "changed_bytes": len(changed),
            "predicted_neutral_white_before_one": False,
            "midgray_unchanged": True,
            "max_random_color_difference": row["random_RGB_max_abs_difference"]}, ensure_ascii=False))
    report = {
        "schema": "a7cr-offline-white-anchor-study/1", "device_access": False,
        "device_install_eligible": False, "firmware_generated": False,
        "installation_package_modified": False, "actual_camera_tested": False,
        "source_model_sha256": sha(model_raw), "neutral_node": NODE,
        "gray_probe_input_encoded_ST": probes,
        "unchanged_domain": "Provisional luminance coordinate <= 0.75; neutral ST input <= 180.25/255 (~0.70686).",
        "rows": rows,
        "limits": [
            "This tests a bounded hypothesis about premature neutral highlight clipping; it is not a finished A7CR calibration.",
            "It does not correct the original DCP rendering bridge or guarantee matching the source DCP.",
            "Saturated colors, preview-only faults and the loaded CP path remain unverified.",
            "The GR Positive table remains unchanged because the original neutral scan did not show early white.",
            "A fixed-exposure ST/look photo comparison and read-only runtime verification must precede selecting a camera experiment.",
            "These loose tables have no device installation entry or firmware patch manifest.",
        ],
    }
    preserve(OUT / "study.private.json", (json.dumps(report, ensure_ascii=False, indent=2)+"\n").encode())
    print("Saved non-installable diagnostic study:", OUT)


if __name__ == "__main__":
    main()
