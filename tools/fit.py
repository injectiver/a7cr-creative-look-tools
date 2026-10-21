"""Offline DCP reference conversion; never creates a firmware install job."""
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path
from .upstream import require


def run(args):
    upstream = require("a7c2")
    sys.path.insert(0, str(upstream / "src/looks"))
    import numpy as np
    from looktool import calibration, native, project
    profile = args.profile.resolve()
    model_path = args.calibration.resolve() if args.calibration else upstream / "src/looks/assets/rendering-model-v1.json"
    model_raw = model_path.read_bytes()
    model = calibration.validate(json.loads(model_raw), True)
    entry = {"source": {"type": "dcp", "path": str(profile),
                         "exposure_stops": model.get("reference_exposure_stops", 0)}}
    render, inventory = project.reference(entry, profile.parent, model)
    os.umask(0o077)
    output = args.output.resolve()
    if output == profile.parent or output in profile.parents:
        raise ValueError("Choose a new output directory separate from input profiles")
    output.mkdir(parents=True, exist_ok=False)
    raw, fit = native.fit_reference(render, model["response_matrix"], seed=201+args.slot)
    if len(raw) != 1215 or not fit["convergence"]["converged"]:
        raise ValueError("Fit did not converge to the expected native table shape")
    coef = native.decode(raw)
    gray = np.repeat(np.linspace(0,1,10001)[:,None], 3, axis=1)
    prediction = native.predict(gray, coef, model["response_matrix"])
    clipped = np.flatnonzero(np.all(prediction >= 1-1e-12, axis=1))
    report = {"schema": "a7cr-public-offline-fit/1", "name": args.name,
        "slot": args.slot, "required_base": "ST", "source_inventory": inventory,
        "model_sha256": hashlib.sha256(model_raw).hexdigest(), "using_shared_upstream_model": bool(args.use_upstream_model),
        "measured_A7CR_accuracy_verified": False, "camera_opened": False,
        "firmware_generated": False, "device_install_eligible": False,
        "native_table_sha256": hashlib.sha256(raw).hexdigest(), "fit": fit,
        "provisional_neutral_first_all_channel_white": None if len(clipped)==0 else float(gray[clipped[0],0]),
        "limits": ["Provisional RGB model; not sensor exposure or IRE.",
                   "LookTable/tone extraction only; not full Adobe RAW rendering.",
                   "ST binding and live camera output require separate validation.",
                   "Derived data retain the input profile's applicable rights; this report grants no redistribution permission."]}
    (output / "slot.raw-s8.private.bin").write_bytes(raw)
    (output / "candidate.private.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
    print(json.dumps({"output": str(output), "bytes": len(raw), "synthetic_rgb_mae": fit["synthetic_holdout"]["rgb_mae"],
                      "camera_opened": False, "device_install_eligible": False}, indent=2))
