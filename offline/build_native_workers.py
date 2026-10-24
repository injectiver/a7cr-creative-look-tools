"""Adapt upstream fixed-window workers to the captured A7CR programs.

The native implementation is from QAQLeonard/a7c2-fl23-research, MIT.
Generated Sony-derived headers and binaries stay under private storage.
Compilation is not authorization to install, and this script never opens USB.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from inspect_sources import ROOT, save_json

UPSTREAM = ROOT / "research/repos/a7c2-fl23-research/src/fl23"
OUT = ROOT / "private/native-workers"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def array(raw):
    return "{"+",".join(f"0x{x:02x}" for x in raw)+"}"


def manifest_header(before, after, sizes, windows):
    lines = ["/* Generated from captured A7CR inputs. Private, not a public firmware payload. */",
             "static const u64 file_sizes[2]="+"{"+",".join(str(s) for s in sizes)+"};",
             "static const u8 original_hashes[2][32]={"+",".join(array(bytes.fromhex(h)) for h in before)+"};",
             "static const u8 final_hashes[2][32]={"+",".join(array(bytes.fromhex(h)) for h in after)+"};"]
    for index, window in enumerate(windows):
        old, new = bytes.fromhex(window["before_hex"]), bytes.fromhex(window["after_hex"])
        if not old or len(old) != len(new) or len(old) > 4096:
            raise ValueError("Invalid native window size")
        lines.extend([f"static const u8 old_{index}[]={array(old)};",
                      f"static const u8 new_{index}[]={array(new)};"])
    rows = [f"{{{w['offset']}UL,{w['bytes']},{w['chip']},old_{i},new_{i}}}" for i, w in enumerate(windows)]
    lines.extend(["static const struct Window windows[]={"+",".join(rows)+"};",
                  f"static const u32 window_count={len(windows)};"])
    return "\n".join(lines)+"\n"


def source(kind, read_only=False):
    name = "installer.c" if kind == "program" else "wbi.c"
    text = (UPSTREAM / "native" / name).read_text().replace("a7c2.", "a7cr.")
    # The same upstream implementation is used for install and inverse;
    # a separate check-only binary rejects every nonzero requested mode.
    if read_only:
        text = text.replace("r.mode=req.mode;", "r.mode=req.mode; if(req.mode) {r.status=-22;return;}", 1)
        if kind == "program":
            text = text.replace("if(!req.mode) {r.phase=9;return;}", "r.phase=9;return; /* Check-only: mutation code below is unreachable. */", 1)
        else:
            text = text.replace("if(!req.mode)return;", "return; /* Check-only: no retained-image mutation path. */", 1)
    text = text.replace("work();", "if(r.cleanup)r.status=r.cleanup;else work();")
    return "/* Derived from QAQLeonard/a7c2-fl23-research; MIT, see LICENSE.txt. */\n"+text


def compile_worker(folder, filename, text, header=None):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "LICENSE.txt").write_bytes((UPSTREAM / "LICENSE").read_bytes())
    (folder / "sha256.h").write_bytes((UPSTREAM / "native/sha256.h").read_bytes())
    if header is not None:
        (folder / "patch_manifest.h").write_text(header)
    src = folder / (filename+".c")
    src.write_text(text)
    dest = folder / (filename+".so")
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(OUT / "zig-global-cache"),
               ZIG_LOCAL_CACHE_DIR=str(folder / "zig-cache"))
    command = [sys.executable, "-m", "ziglang", "cc", "-target", "aarch64-linux-gnu",
               "-shared", "-fPIC", "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
               "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-nostdlib",
               "-Wl,--no-undefined", "-Wl,-Bsymbolic", "-Wl,-z,noexecstack", "-o", str(dest), str(src)]
    subprocess.run(command, env=env, check=True)
    raw = dest.read_bytes()
    if len(raw) > 65536:
        raise ValueError("Worker exceeds the reviewed Jiritsu staging limit")
    with dest.open("rb") as stream:
        elf = ELFFile(stream)
        if elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_DYN":
            raise ValueError("Wrong worker architecture or ELF type")
        dynamic = elf.get_section_by_name(".dynamic")
        if any(tag.entry.d_tag == "DT_NEEDED" for tag in dynamic.iter_tags()):
            raise ValueError("Unexpected dynamic library dependency")
        symbols = list(elf.get_section_by_name(".dynsym").iter_symbols())
        if any(s.name and s["st_shndx"] == "SHN_UNDEF" for s in symbols):
            raise ValueError("Unexpected unresolved worker symbol")
        init = next(s["st_value"] for s in symbols if s.name == "_init")
        dt_init = next(t.entry.d_val for t in dynamic.iter_tags() if t.entry.d_tag == "DT_INIT")
        if init != dt_init:
            raise ValueError("Loader constructor entry differs")
        relocations = [r for section in elf.iter_sections() if section["sh_type"] == "SHT_RELA"
                       for r in section.iter_relocations()]
        if any(r["r_info_type"] != 1027 or r["r_info_sym"] for r in relocations):
            raise ValueError("Only local ELF RELATIVE relocations are allowed")
        if any(segment["p_type"] == "PT_GNU_STACK" and segment["p_flags"] & 1 for segment in elf.iter_segments()):
            raise ValueError("Executable worker stack")
    return {"file": str(dest.relative_to(ROOT)), "bytes": len(raw), "sha256": sha(raw),
            "source_sha256": sha(text.encode()), "constructor": init,
            "relative_relocations": len(relocations), "dynamic_dependencies": []}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    audit = json.loads((ROOT / "private/offline/fl23-candidate/audit.private.json").read_text())
    body = json.loads((ROOT / "private/offline/baseline-body-plan/body-plan.private.json").read_text())
    before, after, sizes = [], [], []
    all_windows = []
    for chip, kind in enumerate(("AP", "CP")):
        spec = audit["programs"][kind]
        if body["source_programs_verified"][kind]["source_sha256"] != spec["source_sha256"]:
            raise ValueError("Body plan and program input differ")
        before.append(spec["source_sha256"]); after.append(spec["candidate_sha256"]); sizes.append(spec["bytes"])
        for window in spec["windows"]:
            all_windows.append(dict(window, chip=chip))
    workers = {}
    workers["program_check"] = compile_worker(OUT / "program-check", "program-check", source("program", True),
                                               manifest_header(before, after, sizes, all_windows))
    # Follow the documented dependency order: CP program, CP parameters, AP
    # program/bindings, then retained-image invalidation. Keep inverse stages.
    cp_after = [before[0], after[1]]
    workers["cp_stage"] = compile_worker(OUT / "cp-stage", "cp-stage", source("program"),
                                         manifest_header(before, cp_after, sizes, [w for w in all_windows if w["chip"] == 1]))
    workers["ap_stage"] = compile_worker(OUT / "ap-stage", "ap-stage", source("program"),
                                         manifest_header(cp_after, after, sizes, [w for w in all_windows if w["chip"] == 0]))
    workers["wbi_check"] = compile_worker(OUT / "wbi-check", "wbi-check", source("wbi", True))
    workers["wbi_stage"] = compile_worker(OUT / "wbi-stage", "wbi-stage", source("wbi"))
    if b"/sys/power/image_drop" in (ROOT / workers["wbi_check"]["file"]).read_bytes():
        raise ValueError("Check-only WBI worker unexpectedly retains the mutation path")
    result = {"schema": "a7cr-native-workers/1", "model": "ILCE-7CR", "version": "2.01",
              "upstream_commit": "b51688deecb56cd34fdd1f2948915cd6ea4e6736",
              "body_binding": body["body_binding"], "compiler": "ziglang 0.13.0",
              "workers": workers, "device_access": False,
              "native_simulation_passed": False, "camera_preflight_passed": False,
              "installation_authorized": False, "installable_package": False}
    save_json(OUT / "workers.private.json", result)
    print(json.dumps({"workers": {k: {x: v[x] for x in ("bytes", "sha256", "relative_relocations")} for k, v in workers.items()},
                      "device_access": False, "installable_package": False}, indent=2), flush=True)


if __name__ == "__main__":
    main()
