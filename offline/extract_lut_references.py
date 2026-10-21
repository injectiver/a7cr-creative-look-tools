"""Extract official resource/loader references without mounting or camera I/O."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tarfile

from inspect_sources import ROOT, save_json, sha256
from extract_components import copy_checked
from fwtool.archive import ext2, fat
from fwtool.sony import fdat

UPSTREAM = ROOT / "research/repos/a7c2-fl23-research/src/looks"
sys.path.insert(0, str(UPSTREAM))
from looktool import resources


def extract(model="ILCE-7CR"):
    source = ROOT / f"private/firmware/{model}_2.01"
    info = json.loads((source / "inspection.private.json").read_text())
    plain = source / "firmware.fdat"
    if sha256(plain) != info["decrypted_sha256"]:
        raise ValueError("Official reference changed")
    out = ROOT / f"private/components/{model}_2.01/lut-references"
    out.mkdir(parents=True, exist_ok=True)
    names = set(json.loads((UPSTREAM / "assets/resource-files.json").read_text()))
    selected = []
    with plain.open("rb") as stream:
        payload = fdat.readFdat(stream)
        with tarfile.open(fileobj=payload.firmware, mode="r:") as archive:
            for part, reader, wanted in (
                ("nflasha15", ext2.readExt2, names),
                ("nflasha8", fat.readFat, {"loader_spi.bin", "mini_ldr.bin"}),
            ):
                content = archive.extractfile(archive.getmember("0700_part_image/dev/"+part))
                found = set()
                for entry in reader(content):
                    name = Path(entry.path).name
                    if name not in wanted:
                        continue
                    if name in found:
                        raise ValueError("Duplicate reference name")
                    found.add(name)
                    item = copy_checked(entry.contents, out/name, entry.size)
                    item.update(partition=part, source_path=entry.path)
                    if name in names:
                        raw = (out/name).read_bytes()
                        parsed = resources.decode(raw)
                        renamed, plan = resources.rename(raw, dict(enumerate(
                            ["Classic Neg.", "Classic Chrome", "Nostalgic Neg.", "Eterna", "GR Positive Film", "GR Negative Film"], 1)),
                            list(range(0x0200ab2c, 0x0200ab32)))
                        if resources.inverse(renamed, plan) != raw:
                            raise ValueError("Official resource inverse differs")
                        item.update(group=parsed["group"], count=parsed["count"],
                                    inverse_exact=True, candidate_bytes=len(renamed))
                    selected.append(item)
                if found != wanted:
                    raise ValueError(f"Missing {part} references: {wanted-found}")
    save_json(out/"references.private.json", {"schema":"a7cr-official-lut-references/1", "model":model,
              "official_package_sha256":info["package_sha256"], "selected":selected,
              "resource_count":len(names), "device_access":False, "body_resources_not_yet_captured":True})
    print(json.dumps({"model":model, "resources_validated_and_inverted":len(names), "loader_files":2}))


if __name__ == "__main__":
    extract(sys.argv[1] if len(sys.argv)>1 else "ILCE-7CR")
