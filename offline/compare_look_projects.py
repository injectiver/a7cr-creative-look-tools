"""Compare the two supplied projects' evidence and local donor records.

No USB, firmware mutation, table fitting or claim of cross-camera color
equivalence. A7CR long records are locally extracted/rebuilt, not distributed
by its documentation-only upstream repository.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct

from inspect_sources import ROOT, save_json


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    os.umask(0o077)
    upstream = ROOT / "research/repos/a7c2-fl23-research"
    colors = json.loads((upstream / "src/fl23/assets/colors.json").read_text())
    donor = json.loads((upstream / "src/fl23/assets/fx2_fl23_donor.json").read_text())
    cr = json.loads((ROOT / "private/offline/fl23-candidate/color-plan.private.json").read_text())["records"]
    color_comparison = []
    for first, second in zip(colors, cr):
        if first["parameter"] != second["parameter"] or first["slot"] != second["bank"]:
            raise ValueError("Look records are not aligned by target parameter/bank")
        row = {"look": "FL2" if first["parameter"] == 55 else "FL3"}
        for key, size in (("chroma", 64), ("matrix", 576)):
            a, b = bytes.fromhex(first[key]), bytes.fromhex(second[key])
            if len(a) != len(b) or len(a) != size:
                raise ValueError("Color record lengths differ")
            row[key] = {"bytes": size, "equal": a == b,
                        "different_bytes": sum(x != y for x, y in zip(a, b)),
                        "a7cii_sha256": sha(a), "a7cr_local_sha256": sha(b)}
        color_comparison.append(row)
    patches = json.loads((upstream / "src/fl23/assets/patches.json").read_text())
    source = next(w for w in patches[1]["writes"] if len(bytes.fromhex(w["after_hex"])) == 3872)
    first_block = bytes.fromhex(source["after_hex"])
    second_program = (ROOT / "private/offline/fl23-candidate/cpapp-b.bin").read_bytes()
    second_block = second_program[0x10FF4A0:0x10FF4A0+3872]
    gamma_comparison = []
    for index in range(4):
        a, b = first_block[index*576:(index+1)*576], second_block[index*576:(index+1)*576]
        tag_a, generation_a = struct.unpack_from("<II", a, 0x218)
        tag_b, generation_b = struct.unpack_from("<II", b, 0x218)
        if tag_a != tag_b or generation_a != generation_b:
            raise ValueError("Gamma records need semantic reordering before comparison")
        gamma_comparison.append({"gamma_id": tag_a >> 24, "generation": generation_a,
                                 "complete_record_equal": a == b,
                                 "curve_payload_equal": a[:0x218] == b[:0x218],
                                 "different_record_bytes": sum(x != y for x, y in zip(a, b)),
                                 "a7cii_sha256": sha(a), "a7cr_local_sha256": sha(b)})
    model = json.loads((upstream / "src/looks/assets/rendering-model-v1.json").read_text())
    report = {
        "schema": "a7cr-a7cii-look-comparison/1", "device_access": False,
        "a7cii_fl23_donor": donor["reference"],
        "a7cr_fl23_donor": {"model": "ILCE-1M2", "firmware": "4.00",
                             "basis": "A7CR README plus locally verified official firmware extraction"},
        "native_color_records": color_comparison, "native_gamma_records": gamma_comparison,
        "interpretation_limits": [
            "This compares the current port implementations and local reconstructed records, not two physical cameras.",
            "Different records do not establish that same-name looks must render differently on the two bodies.",
            "A7CR upstream publishes research notes; omitted long payloads were reconstructed locally.",
            "Same style source does not establish identical fitted native coefficients or final camera colors.",
        ],
        "custom_dcp": {"same_18_original_style_sources_reusable_for_research": True,
                       "do_not_transplant_dcp_camera_calibration_matrices": True,
                       "default_bridge_evidence": model["evidence"],
                       "default_bridge_full_camera_characterization": model["full_camera_characterization"],
                       "a7cr_equivalence_established_in_referenced_docs": False,
                       "a7cr_installer_implemented": False},
        "sources": ["https://github.com/QAQLeonard/a7c2-fl23-research",
                    "https://github.com/lzh2016zzz/a7cr-fl23-research",
                    "https://github.com/QAQLeonard/a7c2-fl23-research/blob/main/docs/en/custom-lut.md"],
    }
    out = ROOT / "private/offline/lut-port/project-comparison.private.json"
    save_json(out, report)
    print(json.dumps({"color_records": [{"look": item["look"], "chroma_equal": item["chroma"]["equal"],
                                           "matrix_equal": item["matrix"]["equal"]} for item in color_comparison],
                      "gamma_records": [{key: item[key] for key in ("gamma_id", "generation", "complete_record_equal")}
                                        for item in gamma_comparison],
                      "same_style_sources_reusable": True, "physical_camera_equivalence_proven": False,
                      "device_access": False}, indent=2))


if __name__ == "__main__":
    main()
