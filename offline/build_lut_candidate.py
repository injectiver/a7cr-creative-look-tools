"""A7CR 2.01 six-look program port. Offline candidate only; never opens USB.

Algorithm and assembly derive from QAQLeonard/a7c2-fl23-research (MIT).
The adapter has separate exact A7CR inputs and preserves installed FL2/FL3.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN
from inspect_sources import ROOT, save_json
sys.path.insert(0, str(ROOT/"research/repos/a7c2-fl23-research/src/looks"))
from looktool import six, sixbuild

OUT = ROOT/"private/offline/lut-port/candidate"
INPUT = ROOT/"private/install/20261020-a7cr-fl23-01/payload"
EXPECTED = {"AP":"4ff7051bfca944b02ce150f911357d5d0173bbf2bfad01a08c9dea13a0dac019",
            "CP":"7c6a4baca721232aefe945ebd080cda5665c6c9488d61fa81849156b9302c446"}
BASE = 0x108000
ENTRY, END, TITLE = 0x3528cd8, 0x3528d5c, 0x3528d28
GETTER, MAP = 0x1b5ce5c, 0x4c7d4cc
HELPER, CHECKER = 0xc2f490, 0xc2ff10


def sha(b):
    return hashlib.sha256(b).hexdigest()


def assembler(arch):
    ks = Ks(arch, KS_MODE_THUMB if arch == KS_ARCH_ARM else KS_MODE_LITTLE_ENDIAN)
    return lambda text, at: bytes(ks.asm(text, addr=at)[0])


def ap_code(mask):
    if type(mask) is not int or mask not in range(64):
        raise ValueError("Expected six-slot mask")
    asm = assembler(KS_ARCH_ARM64)
    converter = asm(";".join([
        "cmp w0,#16", "b.eq special", "cbnz w1,legacy", "sub w0,w0,#10", "cmp w0,#5",
        "b.hi legacy", f"mov w3,#{mask}", "lsr w3,w3,w0", "tbz w3,#0,legacy",
        "add w0,w0,#249", "b store", "legacy:cmp w1,#11", f"b.hi 0x{END:x}",
        f"adrp x0,0x{MAP&~4095:x}", f"add x0,x0,#{MAP&4095}",
        "ldrb w0,[x0,w1,uxtw]", "store:strb w0,[x2]", "ret", "special:mov w0,#-1", "b store"]), ENTRY)
    title = asm(";".join([
        "mov x29,sp", "sub w2,w1,#0x7f8", "cmp w2,#5", "b.hi fallback",
        f"mov w3,#{mask}", "lsr w3,w3,w2", "tbz w3,#0,fallback", "mov w0,#0xab2c",
        "movk w0,#0x200,lsl #16", "add w0,w0,w2", "ldp x29,x30,[sp],#16", "ret",
        f"fallback:b 0x{GETTER+4:x}"]), TITLE)
    if (len(converter), len(title), len(converter+title)) != (80,52,END-ENTRY):
        raise ValueError("A7CR existing function bounds exceeded")
    return converter+title, asm(f"b 0x{TITLE:x}", GETTER)


def cp_code():
    thumb = assembler(KS_ARCH_ARM)
    # Preserve the reviewed v4 helper logic; only native A7CR continuations
    # differ. The common helper/checker addresses remain in the text tail.
    def mapped(text, at):
        for old,new in [("0x240832","0x240852"),("0x23d4e8","0x23d508"),("0x23d516","0x23d536")]:
            text=text.replace(old,new)
        return thumb(text, at)
    helper = bytearray(sixbuild.helper(mapped))
    retry = thumb(";".join(["cbnz r4,0xc2f586", "ldrh.w r0,[r5,#0x188]", "movw r1,#0x201",
                          "cmp r0,r1", "bne 0xc2f586", "b.w 0xc2f578"]), 0xc2f50e)
    tail = thumb(";".join(["ldr.w r0,[r8,#0xc]", "ldr.w r0,[r0,#0x6b0]", "cbz r0,0xc2f586",
                         "b.w 0x23d58c", "movw r0,#0x1760", "b.w 0x23d55e"]), 0xc2f578)
    if len(retry)!=18 or len(tail)!=22:
        raise ValueError("A7CR retry helper bounds differ")
    helper[0x7e:0x7e+len(retry)] = retry
    helper[0xe8:0xe8+len(tail)] = tail
    check = sixbuild.checker(thumb)
    bridge = thumb(";".join([
        "ldr.w r0,[r8]", "ldrb r2,[r0,#1]", "cmp r2,#0", "bne legacy",
        "ldrb.w r2,[r0,#0x2e]", "sub.w r2,r2,#249", "cmp r2,#5", "bhi legacy",
        "ldr r0,[sp,#0x38]", "ldr r0,[r0,#8]", "ldrb.w r2,[r0,#0x188]", "cmp r2,#1", "bne legacy",
        "ldrb.w r2,[r0,#0x189]", "cmp r2,#2", "bne legacy", "movs r1,#4", "mov.w lr,#4",
        "b.w 0x23d8ec", "legacy:movs r5,#0", "b.w 0x23dbb8"]),CHECKER+0x60)
    if len(check)>96 or len(bridge)!=58:
        raise ValueError("A7CR checker/bridge bounds differ")
    return bytes(helper), check+bytes(96-len(check))+bridge


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    before = {k:(INPUT/f"candidate-{k}.private.bin").read_bytes() for k in EXPECTED}
    if any(sha(v)!=EXPECTED[k] for k,v in before.items()):
        raise ValueError("Exact reviewed A7CR FL23 inputs required")
    cii_ap=(ROOT/"private/components/ILCE-7CM2_2.01/appFw.so").read_bytes()
    cii_cp=(ROOT/"private/components/ILCE-7CM2_2.01/cpapp-b.bin").read_bytes()
    assets=json.loads((ROOT/"research/repos/a7c2-fl23-research/src/looks/assets/runtime-v1.json").read_text())
    for kind,raw in (("ap",cii_ap),("cp",cii_cp)):
        spec=next(x for x in assets[kind+"_sources"] if x["kind"]=="stock")
        if sha(raw)!=spec["sha256"]:
            raise ValueError("Official CII comparison source differs from pinned repository")
    ap,cp=(bytearray(before[k]) for k in ("AP","CP"))
    patches={"AP":[],"CP":[]}
    def put(kind,at,old,new,why):
        target=ap if kind=="AP" else cp
        if len(old)!=len(new) or target[at:at+len(old)]!=old or not old:
            raise ValueError(f"{kind} checked patch source/size differs at {at:x}")
        if any(at<w["offset"]+w["bytes"] and at+len(old)>w["offset"] for w in patches[kind]):
            raise ValueError("Overlapping patch windows")
        target[at:at+len(new)]=new
        patches[kind].append(dict(offset=at,bytes=len(old),before_hex=old.hex(),after_hex=new.hex(),purpose=why))
    code,branch=ap_code(63)
    getter_start=cii_ap[0x1b5cd78:0x1b5cd98]
    if before["AP"].count(getter_start)!=1 or before["AP"].find(getter_start)!=GETTER-4:
        raise ValueError("A7CR title getter not uniquely matched")
    put("AP",ENTRY,before["AP"][ENTRY:END],code,"Six-mask ST converter and bounded title helper")
    put("AP",GETTER,bytes.fromhex("fd030091"),branch,"Preserved-frame title getter branch")
    put("AP",MAP,bytes.fromhex("1200020406080a0c0e100000"),bytes([0,3,2,1,16,15,17,18,5,13,19,20]),"Reused original converter-only native map")
    for slot in range(6):
        at=0x59896f0+slot*0xb8
        # Surrounding native menu records are byte-identical to the pinned CII
        # reference; the label ID is then changed for this selected slot only.
        if before["AP"][at-32:at+36]!=cii_ap[at-32:at+36]:
            raise ValueError("A7CR custom label row differs")
        put("AP",at,struct.pack("<I",0x0200a302),struct.pack("<I",0x0200ab2c+slot),"Selected-slot resource label")
    thumb=assembler(KS_ARCH_ARM)
    source=next(x for x in assets["cp_sources"] if x["kind"]=="fl23")
    original=bytes.fromhex(next(w for w in source["windows"] if w["offset"]==0x1354b8)["before"])
    if before["CP"].count(original)!=1 or before["CP"].find(original)!=0x1354d8:
        raise ValueError("A7CR controller block not uniquely matched")
    block=bytearray(original)
    block[:16]=thumb(f"bl 0x{HELPER:x}",0x23d4d8)+bytes.fromhex("00bf")*6
    block[0x1a:0x1c]=thumb("cbz r4,0x23d504",0x23d4f2)
    block[0x2a:0x2c]=thumb("b 0x23d504",0x23d502)
    block[0x2c:0x30]=thumb(f"b.w 0x{HELPER+0x90:x}",0x23d504)
    put("CP",0x1354d8,original,bytes(block),"Dispatch, root+3 incoming boundary repair and preview guard")
    put("CP",0x13555a,thumb("movw r0,#0x1760",0x23d55a),thumb("b.w 0xc2f50e",0x23d55a),"v4 cached-table upload retry")
    put("CP",0x1358e8,thumb("movs r5,#0;b 0x23dbb8",0x23d8e8),thumb("b.w 0xc2ff70",0x23d8e8),"Validated custom-marker switch bridge")
    for at in (0x32338a,0x3234b0):
        old=thumb("bl 0x240852",at+BASE)
        put("CP",at,old,thumb(f"bl 0x{HELPER+0x70:x}",at+BASE),"Normalize custom ST marker, retain A7CR FL23 gamma route")
    helper,checker=cp_code()
    put("CP",HELPER-BASE,bytes(len(helper)),helper,"Guarded six-table helper and preview retry")
    put("CP",CHECKER-BASE,bytes(len(checker)),checker,"Per-use FNV validation and switch bridge")
    tables=[(ROOT/f"private/offline/lut-port/selected-six/slot-{i}.raw-s8.private.bin").read_bytes() for i in range(1,7)]
    data=six.prefix(tables)
    put("CP",0x8000,bytes(len(data)),data,"Six signed 7-bit correction tables with checksums")
    # Only extend loaded executable text inside the pre-existing inter-section
    # gap. Preserve all original initialized data, BSS starts and FL23 gamma.
    if struct.unpack_from("<3I",cp,0x20124)!=(0,0xb072e8,0x128000):
        raise ValueError("Unknown A7CR text descriptor")
    put("CP",0x20128,struct.pack("<I",0xb072e8),struct.pack("<I",0xb07fb0),"Load owned text tail without moving next section or BSS")
    after={"AP":bytes(ap),"CP":bytes(cp)}
    for kind in before:
        inverse=bytearray(after[kind])
        for w in patches[kind]:
            inverse[w["offset"]:w["offset"]+w["bytes"]]=bytes.fromhex(w["before_hex"])
        if bytes(inverse)!=before[kind]:
            raise ValueError("Full program inverse differs")
        (OUT/f"candidate-{kind}.private.bin").write_bytes(after[kind])
    six.read_tables(after["CP"])
    report={"schema":"a7cr-six-program-port/1","device_access":False,"installable":False,
            "model":"ILCE-7CR","version":"2.01","selected_mask":63,"base":"ST",
            "programs":{k:{"source_sha256":sha(before[k]),"candidate_sha256":sha(after[k]),"bytes":len(after[k]),"windows":patches[k]} for k in before},
            "inverse_full_files_exact":True,"original_FL23_assets_and_settings_preserved":True,
            "physical_camera_tested":False,"native_tests_passed":False,"ownership_audit_passed":False,
            "remaining":["Reference/ownership and native path validation","Fresh body-bound checkpoint and live source confirmation","Separate resource and saved recipe transactions"]}
    save_json(OUT/"audit.private.json",report)
    print(json.dumps({"candidate_only":True,"windows":{k:len(patches[k]) for k in patches},"raw_table_bytes":sum(map(len,tables)),"inverse_exact":True}))


if __name__=="__main__":
    build()
