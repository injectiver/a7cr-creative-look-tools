"""Validate and decrypt local Sony updates; never opens a device or executes firmware."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/repos/fwtool-cxd90057"))
try:
    from fwtool.sony import dat, fdat  # noqa: E402
except ModuleNotFoundError:
    dat = fdat = None  # Public host helpers only need save_json; analysis deps are optional.

SOURCES = (
    {
        "model": "ILCE-7CR", "version": "2.01", "bytes": 1_140_252_120,
        "page": "https://service.sony.com.cn/download/firm/00003057.html",
        "url": "https://support.d-imaging.sony.co.jp/download/NEX/jY168ad238/BODYDATA.DAT?fm=cn",
    },
    {
        "model": "ILCE-1M2", "version": "4.00", "bytes": 1_194_332_648,
        "page": "https://service.sony.com.cn/download/firm/00003133.html",
        "url": "https://support.d-imaging.sony.co.jp/download/NEX/lvb4f975ad/BODYDATA.DAT?fm=cn",
    },
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def inventory(stream) -> list[dict]:
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        return [
            {"name": member.name, "bytes": member.size,
             "type": member.type.decode("ascii", "replace")}
            for member in archive
        ]


def inspect(spec: dict) -> dict:
    if dat is None or fdat is None:
        raise RuntimeError("Firmware analysis requires: python a7cr.py bootstrap --research")
    folder = ROOT / "private/firmware" / f'{spec["model"]}_{spec["version"]}'
    package = folder / "BODYDATA.DAT"
    pending = folder / "BODYDATA.DAT.part"
    source = package if package.exists() else pending
    if source.stat().st_size != spec["bytes"]:
        raise ValueError(f'{spec["model"]}: official download size differs')
    print(f'{spec["model"]}: validating outer CRC and computing local SHA-256', flush=True)
    with source.open("rb") as stream:
        outer = dat.readDat(stream)
        normal = [f"{vid:04x}:{pid:04x}" for vid, pid in outer.normalUsbDescriptors]
        updater = [f"{vid:04x}:{pid:04x}" for vid, pid in outer.updaterUsbDescriptors]
    package_hash = sha256(source)
    if not package.exists():
        source.replace(package)
    record_path = folder / "inspection.private.json"
    previous = json.loads(record_path.read_text()) if record_path.exists() else {}
    result = dict(spec, package_sha256=package_hash, outer_crc_valid=True,
                  normal_usb_ids=normal, updater_usb_ids=updater,
                  signature_verification_performed=False,
                  note="SHA-256 is computed locally, not a Sony-published digest.")
    save_json(record_path, result)
    decrypted = folder / "firmware.fdat"
    can_reuse = (decrypted.exists() and previous.get("package_sha256") == package_hash
                 and previous.get("decrypted_sha256") == sha256(decrypted))
    if not can_reuse:
        print(f'{spec["model"]}: decrypting and validating per-block checksums', flush=True)
        with package.open("rb") as stream:
            outer = dat.readDat(stream)
            crypter, plain = fdat.decryptFdat(outer.firmwareData)
            temp = decrypted.with_suffix(".fdat.part")
            count = 0
            started = time.monotonic()
            next_report = 128 * 1024 * 1024
            with temp.open("wb") as output:
                while block := plain.read(1024 * 1024):
                    output.write(block)
                    count += len(block)
                    if count >= next_report:
                        print(f'{spec["model"]}: decrypted {count // (1024*1024)} MiB '
                              f'in {time.monotonic()-started:.1f}s', flush=True)
                        next_report += 128 * 1024 * 1024
                output.flush()
                os.fsync(output.fileno())
            temp.replace(decrypted)
        result["crypter"] = crypter
    else:
        result["crypter"] = previous["crypter"]
    result["decrypted_sha256"] = sha256(decrypted)
    result["decrypted_bytes"] = decrypted.stat().st_size
    with decrypted.open("rb") as stream:
        payload = fdat.readFdat(stream)
        if payload.version != spec["version"]:
            raise ValueError(f'FDAT version mismatch: {payload.version}')
        result.update(fdat_model=f"0x{payload.model:08x}", fdat_version=payload.version,
                      region=payload.region, fdat_header_crc_valid=True,
                      firmware_tar_bytes=payload.firmware.size,
                      updater_fs_bytes=payload.fs.size,
                      members=inventory(payload.firmware))
    result["phase"] = "DECRYPTED_AND_INVENTORIED"
    save_json(record_path, result)
    print(json.dumps({"model": spec["model"], "version": result["fdat_version"],
                      "model_id": result["fdat_model"], "crypter": result["crypter"],
                      "member_count": len(result["members"]),
                      "partitions": [m for m in result["members"]
                                     if m["name"].startswith("0700_part_image/dev/")]
                      }, ensure_ascii=False), flush=True)
    return result


if __name__ == "__main__":
    records = [inspect(spec) for spec in SOURCES]
    save_json(ROOT / "private/offline/sources.private.json", {
        "schema": "a7cr-offline-sources/1", "device_access": False,
        "sources": records,
    })
