"""Extract selected program/default files without mounting or executing firmware."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from stat import S_ISREG
import sys
import tarfile

from inspect_sources import ROOT, SOURCES, save_json, sha256
from fwtool.archive import ext2, fat
from fwtool.sony import fdat


def copy_checked(stream, target: Path, expected: int) -> dict:
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".part")
    count = 0
    digest = hashlib.sha256()
    stream.seek(0)
    with temp.open("wb") as output:
        while block := stream.read(65536):
            count += len(block)
            if count > expected:
                raise ValueError(f"Component exceeds declared size: {target.name}")
            digest.update(block)
            output.write(block)
        output.flush()
        os.fsync(output.fileno())
    if count != expected:
        raise ValueError(f"Truncated component: {target.name}: {count} != {expected}")
    temp.replace(target)
    return {"file": target.name, "bytes": count, "sha256": digest.hexdigest()}


def extract(spec: dict) -> dict:
    tag = f'{spec["model"]}_{spec["version"]}'
    source = ROOT / "private/firmware" / tag
    record = json.loads((source / "inspection.private.json").read_text())
    plain = source / "firmware.fdat"
    if sha256(plain) != record["decrypted_sha256"]:
        raise ValueError("Decrypted source changed")
    out = ROOT / "private/components" / tag
    out.mkdir(parents=True, exist_ok=True)
    inventory = []
    selected = []
    with plain.open("rb") as stream:
        payload = fdat.readFdat(stream)
        if payload.version != spec["version"]:
            raise ValueError("FDAT version changed")
        with tarfile.open(fileobj=payload.firmware, mode="r:") as archive:
            for part, reader, wanted in (
                ("nflasha15", ext2.readExt2, {"appFw.so"}),
                ("nflasha8", fat.readFat, {"cpapp-b.bin"}),
            ):
                member = archive.getmember("0700_part_image/dev/" + part)
                content = archive.extractfile(member)
                if content is None:
                    raise ValueError("Missing partition data")
                found = set()
                for entry in reader(content):
                    inventory.append({"partition": part, "path": entry.path,
                                      "bytes": entry.size, "mode": entry.mode})
                    name = Path(entry.path).name
                    if name in wanted and S_ISREG(entry.mode):
                        if name in found:
                            raise ValueError(f"Ambiguous component {name}")
                        found.add(name)
                        result = copy_checked(entry.contents, out / name, entry.size)
                        result.update(partition=part, source_path=entry.path)
                        selected.append(result)
                        print(tag, result, flush=True)
                if found != wanted:
                    raise ValueError(f"Missing components in {part}: {wanted-found}")
            for member in archive.getmembers():
                if (member.isfile() and member.name.startswith("0110_backup/")
                        and ("ALLLANG" in member.name or member.name.endswith("_CN2.bin"))):
                    content = archive.extractfile(member)
                    result = copy_checked(content, out / Path(member.name).name, member.size)
                    result.update(source_path=member.name,
                                  kind="official_factory_defaults_not_body_backup")
                    selected.append(result)
    result = {"schema": "a7cr-components/1", "model": spec["model"],
              "version": spec["version"], "device_access": False,
              "package_sha256": record["package_sha256"], "selected": selected,
              "inventory": inventory}
    save_json(out / "components.private.json", result)
    return result


if __name__ == "__main__":
    for spec in SOURCES:
        extract(spec)
