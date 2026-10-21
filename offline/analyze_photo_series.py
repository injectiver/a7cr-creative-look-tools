"""Read copied RAW/JPEG exposure samples; generate statistics and small previews.

No camera session, original-file changes, or firmware operations. Pixel mapping
uses the RAW default crop and does not undo JPEG lens corrections, so overlap
counts are approximate. Raw saturation counts themselves are directly measured.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
from PIL import Image
import rawpy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("stems", nargs="+")
    args = parser.parse_args()
    os.umask(0o077)
    folder = args.directory.resolve()
    metadata = json.loads((folder / "capture-metadata.private.json").read_text())
    meta = {Path(x["SourceFile"]).stem: x for x in metadata if x["SourceFile"].endswith(".JPG")}
    rows = []
    for stem in args.stems:
        m = meta[stem]
        with rawpy.imread(str(folder / (stem+".ARW"))) as raw:
            s = raw.sizes
            a = raw.raw_image_visible[s.crop_top_margin:s.crop_top_margin+s.crop_height,
                                      s.crop_left_margin:s.crop_left_margin+s.crop_width]
            if a.shape != (s.crop_height, s.crop_width) or a.shape[0] % 2 or a.shape[1] % 2:
                raise ValueError("Unexpected RAW crop")
            planes = [a[dy::2, dx::2] for dy, dx in [(0,0),(0,1),(1,0),(1,1)]]
            all_sat = np.logical_and.reduce([p >= raw.white_level for p in planes])
            any_sat = np.logical_or.reduce([p >= raw.white_level for p in planes])
            histogram = np.bincount(a.ravel(), minlength=65536)
            cs = histogram.cumsum()
            row = {"file": stem, "seconds": m["ExifIFD:ExposureTime"],
                "ISO": m["ExifIFD:ISO"], "FNumber": m["ExifIFD:FNumber"],
                "native_look_mode": m["Sony:CreativeStyle"], "gamma_metadata": m["Sony:PictureProfile"],
                "highlights_setting": m["Sony:Highlights"], "raw_white_level": raw.white_level,
                "camera_white_level_per_channel": raw.camera_white_level_per_channel,
                "black_level_per_channel": raw.black_level_per_channel,
                "camera_whitebalance": raw.camera_whitebalance,
                "raw_max": int(a.max()),
                "raw_quantiles": {str(q): int(np.searchsorted(cs, q*a.size)) for q in [.5,.99,.999,.9999]},
                "raw_photosites_at_white_pct": float(histogram[raw.white_level:].sum()/a.size*100),
                "raw_all_four_saturated_block_pct": float(all_sat.mean()*100),
                "raw_any_saturated_block_pct": float(any_sat.mean()*100)}
            with Image.open(folder / (stem+".JPG")) as im:
                if im.size != (s.crop_width, s.crop_height):
                    raise ValueError("JPEG dimensions differ from RAW default crop")
                j = np.asarray(im.convert("RGB"))
                row["jpeg_threshold_percentages"] = {
                    str(v): {"all_channels": float(np.mean(np.all(j >= v, axis=2))*100),
                             "any_channel": float(np.mean(np.any(j >= v, axis=2))*100)}
                    for v in [245,250,254,255]}
                row["jpeg_max_per_channel"] = j.max(axis=(0,1)).tolist()
                half = np.asarray(im.resize((a.shape[1]//2, a.shape[0]//2), Image.Resampling.BOX).convert("RGB"))
                white = np.all(half >= 254, axis=2)
                row["jpeg_half_white_block_pct"] = float(white.mean()*100)
                row["jpeg_half_white_blocks_with_no_RAW_channel_at_white_pct"] = float(np.mean(white & ~any_sat)*100)
                preview = im.convert("RGB")
                preview.thumbnail((1400, 1000), Image.Resampling.LANCZOS)
                preview.save(folder / (stem+".preview.jpg"), quality=94)
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    result = {"schema": "a7cr-photo-exposure-series/1", "device_access": False,
        "original_files_modified": False, "rawpy": rawpy.__version__, "libraw": rawpy.libraw_version,
        "spatial_overlap_is_approximate": True, "rows": rows}
    (folder / "exposure-analysis.private.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n")


if __name__ == "__main__":
    main()
