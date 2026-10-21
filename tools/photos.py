"""Analyze explicitly selected RAW+JPEG pairs without editing the originals."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
from .upstream import require

TAGS = ("FileName", "Model", "DateTimeOriginal", "ExposureTime", "FNumber", "ISO",
        "ExposureCompensation", "ExposureMode", "WhiteBalance", "WBShiftAB_GM",
        "ColorSpace", "CreativeStyle", "ColorMode", "PictureProfile", "Contrast",
        "Highlights", "Shadows", "Fade", "Saturation", "Sharpness", "SharpnessRange",
        "Clarity", "DynamicRangeOptimizer", "HDR")


def validate_stems(stems):
    if not stems or len(set(stems)) != len(stems):
        raise ValueError("Supply distinct camera filename stems")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", s) for s in stems):
        raise ValueError("Filename stems cannot contain paths, extensions, or traversal")


def run(args):
    import numpy as np
    import rawpy
    from PIL import Image, ImageOps
    validate_stems(args.stems)
    source = args.input.resolve()
    paths = []
    for stem in args.stems:
        for ext in ("JPG", "ARW"):
            p = source / (stem+"."+ext)
            if not p.is_file():
                raise ValueError("Missing RAW+JPEG pair: " + p.name)
            paths.append(p)
    exif = args.exiftool.resolve() if args.exiftool else require("exiftool") / "exiftool"
    command = (["perl", str(exif)] if exif.name == "exiftool" else [str(exif)])
    command += ["-config", "", "-j", "-G1", "-n"] + ["-"+x for x in TAGS] + list(map(str, paths))
    metadata_raw = subprocess.check_output(command)
    metadata = json.loads(metadata_raw)
    capture = {Path(x["SourceFile"]).stem: x for x in metadata if x["SourceFile"].endswith(".JPG")}
    output = args.output.resolve()
    if output == source or output in source.parents:
        raise ValueError("Choose a new output directory separate from input originals")
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False)
    (output / "capture-metadata.private.json").write_bytes(metadata_raw)
    rows = []
    for stem in args.stems:
        with rawpy.imread(str(source / (stem+".ARW"))) as raw:
            size = raw.sizes
            a = raw.raw_image_visible[size.crop_top_margin:size.crop_top_margin+size.crop_height,
                                       size.crop_left_margin:size.crop_left_margin+size.crop_width]
            if raw.raw_pattern is None or raw.raw_pattern.shape != (2,2) or any(x % 2 for x in a.shape):
                raise ValueError("This analysis supports an even-sized 2x2 Bayer crop")
            histogram = np.bincount(a.ravel(), minlength=65536)
            cumulative = histogram.cumsum()
            planes = [a[y::2,x::2] for y,x in ((0,0),(0,1),(1,0),(1,1))]
            all_sat = np.logical_and.reduce([p >= raw.white_level for p in planes])
            any_sat = np.logical_or.reduce([p >= raw.white_level for p in planes])
            row = {"file": stem, "capture": {k:v for k,v in capture[stem].items() if k != "SourceFile"},
                "raw_white_level": raw.white_level, "camera_white_level_per_channel": raw.camera_white_level_per_channel,
                "black_level_per_channel": raw.black_level_per_channel, "camera_whitebalance": raw.camera_whitebalance,
                "raw_max": int(a.max()), "raw_quantiles": {str(q):int(np.searchsorted(cumulative,q*a.size)) for q in (.5,.99,.999,.9999)},
                "raw_photosites_at_white_pct": float(histogram[raw.white_level:].sum()/a.size*100),
                "raw_all_four_saturated_block_pct": float(all_sat.mean()*100),
                "raw_any_saturated_block_pct": float(any_sat.mean()*100)}
            with Image.open(source / (stem+".JPG")) as image:
                if image.size != (size.crop_width,size.crop_height):
                    raise ValueError("JPEG dimensions do not match the RAW default crop")
                pixels = np.asarray(image.convert("RGB"))
                row["jpeg_threshold_percentages"] = {
                    str(v): {"all_channels": float(np.mean(np.all(pixels>=v,axis=2))*100),
                             "any_channel": float(np.mean(np.any(pixels>=v,axis=2))*100)}
                    for v in (245,250,254,255)}
                preview = ImageOps.exif_transpose(image).convert("RGB")
                preview.thumbnail((1400,1000),Image.Resampling.LANCZOS)
                preview.save(output / (stem+".preview.private.jpg"),quality=94)
        rows.append(row)
        print(json.dumps({"file":stem, "RAW_at_white_pct":row["raw_photosites_at_white_pct"],
                          "JPEG_all_RGB_255_pct":row["jpeg_threshold_percentages"]["255"]["all_channels"]}),flush=True)
    report = {"schema":"a7cr-photo-analysis/1", "camera_opened":False,
        "original_files_modified":False, "rawpy":rawpy.__version__, "libraw":rawpy.libraw_version,
        "rows":rows, "limits":[
            "RAW saturation and JPEG white percentages measure different representations.",
            "Different captures are not registered pixel-identical inputs.",
            "JPEG lens corrections may change geometry; no pixelwise RAW/JPEG registration is claimed.",
            "A JPEG value of 255 is not by itself proof of RAW sensor saturation.",
            "This does not establish matching to a physical Alpha 1 II or diagnose every possible gamma defect."]}
    (output / "analysis.private.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print("Local analysis saved:",output)
