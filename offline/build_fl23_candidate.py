"""Build an OFFLINE-ONLY A7CR 2.01 candidate and exercise selected CPU paths.

No USB, camera service, installer or firmware-update container is produced.
Sony-derived bytes, candidates and manifests remain in ignored private storage.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_ARM64, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC
from unicorn.arm64_const import UC_ARM64_REG_W0, UC_ARM64_REG_W1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_PC

from inspect_sources import ROOT, save_json

LOAD = 0x108000
TARGET = ROOT / "private/components/ILCE-7CR_2.01"
DONOR = ROOT / "private/components/ILCE-1M2_4.00"
OUT = ROOT / "private/offline/fl23-candidate"
NOTES = ROOT / "research/repos/a7cr-fl23-research/README.md"
UPSTREAM = ROOT / "research/repos/a7c2-fl23-research/src/fl23/assets/patches.json"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checked_component(folder: Path, name: str) -> bytes:
    manifest = json.loads((folder / "components.private.json").read_text())
    entry = next(item for item in manifest["selected"] if item["file"] == name)
    raw = (folder / name).read_bytes()
    if len(raw) != entry["bytes"] or digest(raw) != entry["sha256"]:
        raise ValueError(f"Source component changed: {folder.name}/{name}")
    return raw


def windows(section: str, end: str) -> list[dict]:
    scope = NOTES.read_text().split(section, 1)[1].split(end, 1)[0]
    result = []
    for line in scope.splitlines():
        fields = [part.strip() for part in line.strip("|").split("|")]
        if not fields or not re.fullmatch(r"`0x[0-9a-f]+`", fields[0]):
            continue
        item = {"offset": int(fields[0].strip("`"), 16), "bytes": int(fields[1])}
        match = re.search(r"`([0-9a-f]+)`\s*->\s*`([0-9a-f]+)`", line)
        if match:
            item.update(before=bytes.fromhex(match[1]), after=bytes.fromhex(match[2]))
            if len(item["before"]) != item["bytes"] or len(item["after"]) != item["bytes"]:
                raise ValueError("Documented window length differs")
        result.append(item)
    return result


def thumb_constant(reg: int, value: int, upper: bool = False) -> bytes:
    first = (0xF2C0 if upper else 0xF240) | ((value >> 12) & 15) | (((value >> 11) & 1) << 10)
    second = (((value >> 8) & 7) << 12) | (reg << 8) | (value & 255)
    return struct.pack("<HH", first, second)


def thumb_machine(data: bytes) -> Uc:
    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    machine.mem_map(LOAD, (len(data) + 4095) & ~4095)
    machine.mem_write(LOAD, data)
    machine.mem_map(0x30000000, 0x2000)
    machine.mem_write(0x30000000, struct.pack("<I", 0x30001000))
    return machine


def name_pointer(machine: Uc, start: int, end: int, mode: int) -> int:
    machine.reg_write(UC_ARM_REG_R2, mode)
    machine.emu_start((LOAD + start) | 1, LOAD + end, count=80)
    if machine.reg_read(UC_ARM_REG_PC) != LOAD+end:
        raise ValueError("Name helper did not reach its original copy continuation")
    return machine.reg_read(UC_ARM_REG_R1)


def original_name_table(cp: bytes) -> tuple[list[int], int]:
    machine = thumb_machine(cp)
    pointers = [name_pointer(machine, 0x148E7E, 0x148F0C, mode) for mode in range(21)]
    off = name_pointer(machine, 0x148E7E, 0x148F0C, 255)
    return pointers, off


def metadata_windows(cp: bytes) -> dict[int, bytes]:
    pointers, off_pointer = original_name_table(cp)
    original_machine = thumb_machine(cp)
    root_pointers = [name_pointer(original_machine, 0x149E34, 0x149EA4, mode) for mode in range(28)]
    differences = [mode for mode in range(19)
                   if original_machine.mem_read(pointers[mode], 16)
                   != original_machine.mem_read(root_pointers[mode], 16)]
    if differences != [0, 1, 12]:
        raise ValueError("Original metadata writers need a different exact-byte adaptation")
    root_off = name_pointer(original_machine, 0x149E34, 0x149EA4, 255)
    pointers[19:21] = [LOAD + 0x149E80, LOAD + 0x149E90]
    # Preserve two incoming branch entry points identified in the A7CR notes.
    preserved = cp[0x148EA0:0x148EA4]
    if preserved != bytes.fromhex("0122bfe7"):
        raise ValueError("Preserved metadata branch differs")
    asm = f""".syntax unified
.cpu cortex-a9
.thumb
.text
.org 0x148e7e
    cmp r2, #20
    bhi .Lfallback
    adr.w r1, .Ltable
    ldr.w r1, [r1, r2, lsl #2]
    b .Lcopy1
.Lfallback:
    cmp r2, #255
    ite eq
    ldreq r1, .Loff
    ldrne r1, .Ltable
    b .Lcopy1
.org 0x148e9c
.Loff: .word {off_pointer}
.org 0x148ea0
    .byte {', '.join(str(x) for x in preserved)}
.org 0x148ea4
.Ltable: .space 84
.org 0x148ef8
    .byte {', '.join(str(x) for x in bytes.fromhex('152901d88a1c18e0002216e000bf00bf00bf00bf'))}
.org 0x148f0c
.Lcopy1:
.org 0x149e34
    cmp r2, #1
    beq .Lvivid
    cmp r2, #12
    beq .Lstandard
    cmp r2, #0
    beq .Lstandard
    cmp r2, #20
    bls .Llookup
    cmp r2, #27
    beq .Lbw
    cmp r2, #255
    beq .Loff2
    b .Lstandard
.Lbw:
    movs r2, #5
.Llookup:
    movw r1, #{(LOAD+0x148ea4) & 65535}
    movt r1, #{(LOAD+0x148ea4) >> 16}
    ldr.w r1, [r1, r2, lsl #2]
    b .Lcopy2
.Lstandard:
    ldr r1, .Lstandard_literal
    b .Lcopy2
.Lvivid:
    ldr r1, .Lvivid_literal
    b .Lcopy2
.Loff2:
    ldr r1, .Loff_literal
    b .Lcopy2
.balign 4
.Lstandard_literal: .word {root_pointers[0]}
.Lvivid_literal: .word {root_pointers[1]}
.Loff_literal: .word {root_off}
.org 0x149e80
    .ascii "FL2"
    .space 13
.org 0x149e90
    .ascii "FL3"
    .space 13
.org 0x149ea4
.Lcopy2:
"""
    src, obj = OUT / "metadata.private.S", OUT / "metadata.private.o"
    src.write_text(asm)
    subprocess.run(["/Library/Developer/CommandLineTools/usr/bin/clang", "-target", "armv7-none-eabi",
                    "-mthumb", "-c", str(src), "-o", str(obj)], check=True)
    with obj.open("rb") as stream:
        elf = ELFFile(stream)
        if any(section["sh_type"] in ("SHT_REL", "SHT_RELA") and section["sh_size"]
               for section in elf.iter_sections()):
            raise ValueError("Unresolved assembly relocations")
        text = bytearray(elf.get_section_by_name(".text").data())
    struct.pack_into("<21I", text, 0x148EA4, *pointers)
    return {0x148E7E: bytes(text[0x148E7E:0x148F0C]),
            0x149E34: bytes(text[0x149E34:0x149EA4])}


def gamma_block(target: bytes, donor: bytes) -> tuple[bytes, list[dict]]:
    block = bytearray(3872)
    records = []
    for gamma in (48, 49):
        for generation in (3, 6):
            found = []
            for match in re.finditer(re.escape(struct.pack("<I", (gamma << 24) | 0x10010)), donor):
                tag_at = match.start()
                gen, maximum = struct.unpack_from("<II", donor, tag_at + 4)
                if gen == generation and 120000 < maximum < 140000:
                    found.append(tag_at - 0x218)
            if len(found) != 1:
                raise ValueError("Ambiguous donor gamma record")
            offset = found[0]
            raw = donor[offset:offset+580]
            if raw[0x238:0x23C] != bytes(4) or any(raw[0x228:0x234]):
                raise ValueError("Donor gamma has target-specific pointers requiring relocation")
            native = bytearray(raw[:0x238] + raw[0x23C:])
            struct.pack_into("<I", native, 0x21C, 5 if generation == 3 else 6)
            index = len(records)
            block[index*576:(index+1)*576] = native
            records.append({"gamma": gamma, "donor_generation": generation,
                            "target_generation": 5 if generation == 3 else 6,
                            "donor_file_offset": offset, "bytes": 576,
                            "sha256": digest(native)})
    # The stock table has 47 rows. Row 47 stays empty; new rows are 48 and 49.
    block[0x900:0x900+47*28] = target[0xFFF884:0xFFF884+47*28]
    base = LOAD + 0x10FF4A0
    for index, gamma in enumerate((48, 49)):
        struct.pack_into("<7I", block, 0x900+gamma*28,
                         *([base + index*1152]*6 + [base + index*1152+576]))
    routes = bytearray(target[0xCFCF74:0xCFCF74+21*8])
    struct.pack_into("<4I", routes, 19*8, 48, 48, 49, 49)
    block[0xE78:] = routes
    return bytes(block), records


def changed_windows(before: bytes, after: bytes) -> list[dict]:
    spans = []
    start = last = None
    for offset, (a, b) in enumerate(zip(before, after)):
        if a == b:
            continue
        if start is None:
            start = offset
        elif offset-last > 16 or offset-start >= 4096:
            spans.append((start, last+1))
            start = offset
        last = offset
    if start is not None:
        spans.append((start, last+1))
    return [{"offset": lo, "bytes": hi-lo, "before_hex": before[lo:hi].hex(),
             "after_hex": after[lo:hi].hex()} for lo, hi in spans]


def exercise_metadata(before: bytes, after: bytes) -> dict:
    old, new = thumb_machine(before), thumb_machine(after)
    names = 0
    for start, end in ((0x148E7E, 0x148F0C), (0x149E34, 0x149EA4)):
        for mode in range(256):
            old_ptr, new_ptr = name_pointer(old, start, end, mode), name_pointer(new, start, end, mode)
            original, actual = bytes(old.mem_read(old_ptr, 16)), bytes(new.mem_read(new_ptr, 16))
            expected = (f"FL{mode-17}".encode()+bytes(13)) if mode in (19, 20) else original
            if actual != expected:
                raise ValueError(f"Metadata mismatch at {start:x}, mode {mode}: {actual!r} != {expected!r}")
            names += 1
    color_modes = 0
    for mode in range(256):
        values = []
        for machine in (old, new):
            machine.mem_write(0x3000103F, bytes([mode]))
            machine.reg_write(UC_ARM_REG_R5, 0x30000000)
            machine.emu_start((LOAD+0x148F12)|1, LOAD+0x148F32, count=60)
            values.append(machine.reg_read(UC_ARM_REG_R2))
        expected = {19: 22, 20: 23}.get(mode, values[0])
        if values[1] != expected:
            raise ValueError(f"Playback ColorMode mismatch: {mode}: {values}")
        color_modes += 1
    return {"name_cases": names, "playback_color_mode_cases": color_modes}


def exercise_ap(before: bytes, after: bytes) -> dict:
    def make(data):
        machine = Uc(UC_ARCH_ARM64, 0)
        for lo in (0x3528000, 0x4C7D000):
            machine.mem_map(lo, 0x1000)
            machine.mem_write(lo, data[lo:lo+0x1000])
        machine.mem_map(0x30000000, 0x2000)
        return machine
    old, new = make(before), make(after)
    expected_modes = [0, 3, 2, 1, 16, 15, 17, 18, 5, 13, 19, 20]
    checked = 0
    for special in (0, 16):
        for look in range(256):
            outcomes = []
            for machine in (old, new):
                machine.mem_write(0x30000000, b"\x7e")
                machine.reg_write(UC_ARM64_REG_W0, special)
                machine.reg_write(UC_ARM64_REG_W1, look)
                machine.reg_write(UC_ARM64_REG_X2, 0x30000000)
                machine.reg_write(UC_ARM64_REG_X30, 0x30001000)
                # Invalid ordinary values preserve the original diagnostic path.
                limit = 9 if machine is old else 11
                stop = 0x3528D5C if special != 16 and look > limit else 0x30001000
                machine.emu_start(0x3528CD8, stop, count=100)
                if machine.reg_read(UC_ARM64_REG_PC) != stop:
                    raise ValueError("AP helper did not reach the expected return/diagnostic continuation")
                outcomes.append(bytes(machine.mem_read(0x30000000, 1))[0])
            expected = 255 if special == 16 else (expected_modes[look] if look < 12 else outcomes[0])
            if outcomes[1] != expected or (special == 0 and look < 10 and outcomes[0] != outcomes[1]):
                raise ValueError(f"AP converter mismatch: {special}, {look}: {outcomes}")
            checked += 1
    return {"ap_converter_cases": checked}


def exercise_cp_dispatch(before: bytes, after: bytes) -> dict:
    old, new = thumb_machine(before), thumb_machine(after)
    helpers = 0
    for context in (0, 1):
        for mode in range(256):
            new.reg_write(UC_ARM_REG_R0, mode)
            new.reg_write(UC_ARM_REG_R4, context)
            new.reg_write(UC_ARM_REG_LR, 0x30000001)
            new.emu_start((LOAD+0x138852)|1, 0x30000000, count=30)
            if (new.reg_read(UC_ARM_REG_PC) != 0x30000000
                    or new.reg_read(UC_ARM_REG_R0) != mode
                    or new.reg_read(UC_ARM_REG_R1) != LOAD+0x10FF4A0+0xE78):
                raise ValueError("Gamma route helper changed the requested mode or returned a wrong table")
            helpers += 1
    whitelist_cases = 0
    for start, size, register in ((0x64950E, 16, UC_ARM_REG_R6),
                                   (0x64986A, 26, UC_ARM_REG_R5)):
        def destination(machine, parameter):
            result = []
            def trace(uc, address, instruction_size, unused):
                if not LOAD+start <= address < LOAD+start+size:
                    result.append(address)
                    uc.emu_stop()
            handle = machine.hook_add(UC_HOOK_CODE, trace)
            try:
                machine.reg_write(UC_ARM_REG_SP, 0x30001000)
                machine.reg_write(UC_ARM_REG_R0, 0)
                # The real function prologue zeroes r0/r1 before this window.
                machine.reg_write(UC_ARM_REG_R1, 0)
                machine.reg_write(register, parameter)
                machine.emu_start((LOAD+start)|1, 0x30000000, count=30)
                if len(result) != 1:
                    raise ValueError("Whitelist did not reach a known continuation")
                return result[0]
            finally:
                machine.hook_del(handle)
        allowed = destination(old, 54)
        for parameter in range(256):
            expected = allowed if parameter in (55, 56) else destination(old, parameter)
            if destination(new, parameter) != expected:
                raise ValueError(f"Whitelist preservation mismatch: {start:x}, {parameter}")
            whitelist_cases += 1
    return {"gamma_route_helper_cases": helpers, "chroma_whitelist_cases": whitelist_cases}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ap, cp = checked_component(TARGET, "appFw.so"), checked_component(TARGET, "cpapp-b.bin")
    donor = checked_component(DONOR, "cpapp-b.bin")
    specs = {"AP": windows("## 2. AP:", "## 3. CP:"),
             "CP": windows("## 3. CP:", "### Separate photo-name fixes")}
    public = json.loads(UPSTREAM.read_text())
    audit = []
    results = {}
    for kind, original in (("AP", ap), ("CP", cp)):
        candidate = bytearray(original)
        for window in specs[kind]:
            if "before" in window:
                at, size = window["offset"], window["bytes"]
                if original[at:at+size] != window["before"]:
                    raise ValueError(f"Documented {kind} precondition mismatch: {at:x}")
                candidate[at:at+size] = window["after"]
                audit.append({"component": kind, "offset": at, "bytes": size, "match": True})
        results[kind] = candidate
    converter = next(w for w in public[0]["writes"] if w["purpose"] == "ordinary look to CP mode converter")
    results["AP"][0x3528CEC:0x3528CEC+112] = bytes.fromhex(converter["after_hex"])
    for target_offset, reference_offset in ((0x64950E, 0x6492F6), (0x64986A, 0x649652)):
        window = next(w for w in public[1]["writes"] if int(w["file_offset"], 16) == reference_offset)
        old, new = bytes.fromhex(window["before_hex"]), bytes.fromhex(window["after_hex"])
        if cp[target_offset:target_offset+len(old)] != old:
            raise ValueError("Whitelist implementation differs; cannot reuse local branch layout")
        results["CP"][target_offset:target_offset+len(new)] = new
    route_va = LOAD + 0x10FF4A0 + 0xE78
    helper = bytes.fromhex("00bf")*7 + thumb_constant(1, route_va & 65535) + thumb_constant(1, route_va >> 16, True) + bytes.fromhex("704700bf")
    results["CP"][0x138852:0x138852+26] = helper
    block, records = gamma_block(cp, donor)
    if any(cp[0x10FF4A0:0x10FF4A0+len(block)]):
        raise ValueError("Documented append window is occupied")
    results["CP"][0x10FF4A0:0x10FF4A0+len(block)] = block
    for offset, raw in metadata_windows(cp).items():
        results["CP"][offset:offset+len(raw)] = raw
    if cp[0x148F1E:0x148F20] != bytes.fromhex("07d8"):
        raise ValueError("Original playback out-of-range branch differs")
    results["CP"][0x148F1E:0x148F20] = bytes.fromhex("ebd8")
    ap_after, cp_after = bytes(results["AP"]), bytes(results["CP"])
    tests = (exercise_ap(ap, ap_after) | exercise_metadata(cp, cp_after)
             | exercise_cp_dispatch(cp, cp_after))
    manifests = {}
    for kind, filename, original, candidate in (("AP", "appFw.so", ap, ap_after), ("CP", "cpapp-b.bin", cp, cp_after)):
        if len(candidate) != len(original):
            raise ValueError("Candidate file length changed")
        changes = changed_windows(original, candidate)
        inverse = bytearray(candidate)
        for change in changes:
            at, size = change["offset"], change["bytes"]
            if inverse[at:at+size].hex() != change["after_hex"]:
                raise ValueError("Inverse precondition differs")
            inverse[at:at+size] = bytes.fromhex(change["before_hex"])
        if bytes(inverse) != original:
            raise ValueError("Complete-file inverse differs")
        (OUT / filename).write_bytes(candidate)
        manifests[kind] = {"file": filename, "bytes": len(original), "source_sha256": digest(original),
                           "candidate_sha256": digest(candidate), "windows": changes,
                           "inverse_roundtrip_exact": True,
                           "actual_changed_bytes": sum(a != b for a, b in zip(original, candidate))}
    report = {"schema": "a7cr-fl23-offline/1", "model": "ILCE-7CR", "version": "2.01",
              "device_access": False, "installable_package": False,
              "physical_validation_performed": False, "source_windows": audit,
              "gamma_records": records, "cpu_checks": tests, "programs": manifests,
              "remaining": ["Fresh body-specific Backup merge and duplicate backups",
                            "A7CR-specific Mac USB/native preflight and readback workflow",
                            "Complete loading/boot, preview and photo validation",
                            "Custom photo LUT port is a separate subsequent stage"]}
    save_json(OUT / "audit.private.json", report)
    print(json.dumps({"source_windows_matched": len(audit), "cpu_checks": tests,
                      "programs": {kind: {key: value for key, value in spec.items() if key != "windows"}
                                   for kind, spec in manifests.items()},
                      "installable_package": False}, indent=2), flush=True)


if __name__ == "__main__":
    main()
