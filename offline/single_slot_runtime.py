"""Exact-source A7CR slot-1 native menu synchronization preparation.

Static Capstone evidence, not a camera execution or a complete RTOS model.
The menu sequence is derived from QAQLeonard's v3.0.3 look_bindings.c (MIT).
No USB imports. Building a writer requires fresh native before-value evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(ROOT / "offline"))
from build_native_workers import compile_worker

AP_HASH = "4ff7051bfca944b02ce150f911357d5d0173bbf2bfad01a08c9dea13a0dac019"
PROC_HASH = "afe7953b9e91803db635aac7df713dd50677013d4ebe1bd763dcfc93416363d8"
AP_PATH = ROOT / "private/install/fl23/payload/candidate-AP.private.bin"
FUNCTIONS = {
    "context_enter": (0x178FA30, 0x24),
    "context_leave": (0x178FA54, 0x2C),
    "lock": (0x2E07118, 0x40),
    "unlock": (0x2E06D24, 0x40),
    "values_getter": (0x287F1D4, 0x14),
    "info_getter": (0x287F1E8, 0x14),
    "current_getter": (0x2869A10, 0x14),
    "record": (0x3683590, 0x40),
    "notify": (0x25071B4, 0x40),
    "notice": (0x25063DC, 8),
    "menu_setter": (0x2614E54, 0x1A0),
    "change_destructor": (0x2614E20, 0x34),
}
CURRENT_VA, VALUES_VA, INFO_VA = 0x7E70598, 0x7EAC508, 0x7EAC550


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def instructions(raw, offset, size):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    result = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(raw[offset:offset+size], offset))
    if sum(i.size for i in result) != size or any(i.size != 4 for i in result):
        raise ValueError("Undecoded native menu bytes")
    return result


def branch(raw, address):
    i = instructions(raw, address, 4)[0]
    if i.mnemonic not in ("b", "bl") or not i.op_str.startswith("#0x"):
        raise ValueError("Reviewed menu edge is not a direct branch")
    return int(i.op_str[1:], 16)


def getter(raw, name):
    at, n = FUNCTIONS[name]
    rows = instructions(raw, at, n)
    value = None
    for i in rows:
        if i.mnemonic == "adrp" and i.op_str.startswith("x0, #0x"):
            value = int(i.op_str.split("#")[1], 16)
        elif i.mnemonic == "add" and i.op_str.startswith("x0, x0, #") and value is not None:
            tail = i.op_str.split("#", 1)[1]
            immediate = int(tail.split(",")[0], 0)
            value += immediate << (12 if "lsl #12" in i.op_str else 0)
        elif i.mnemonic == "ret":
            return value
        else:
            raise ValueError("Native pointer accessor shape differs")
    raise ValueError("Pointer accessor has no return")


def audit(raw):
    if sha(raw) != AP_HASH:
        raise ValueError("Requires the complete, already-verified A7CR FL23 AP")
    edges = {
        0x2614E7C: "context_enter", 0x2614E84: "lock",
        0x2614E88: "current_getter", 0x2614F2C: "values_getter",
        0x2614F34: "info_getter", 0x2614F88: "record",
        0x2614FB4: "change_destructor", 0x2614FBC: "unlock",
        0x2614FC4: "context_leave", 0x2614FCC: "notice",
        0x2614FEC: "record", 0x2614E4C: "notify",
        0x178FA40: "lock", 0x178FA7C: "unlock",
    }
    for at, name in edges.items():
        if branch(raw, at) != FUNCTIONS[name][0]:
            raise ValueError("Original A7CR menu call graph differs")
    pointers = {name: getter(raw, name) for name in ("current_getter", "values_getter", "info_getter")}
    if list(pointers.values()) != [CURRENT_VA, VALUES_VA, INFO_VA]:
        raise ValueError("Native AP model location differs")
    # Descriptor index 10 is custom slot 1's native base; no other index is writable.
    row = struct.unpack_from("<8I", raw, 0x57C6710+10*32)
    if row[:3] != (3, 0x02CF0CD0, 0x10000) or row[6] != 0x14F4:
        raise ValueError("Slot 1 descriptor identity differs")
    guards = [dict(name=name, offset=at, bytes=n, sha256=sha(raw[at:at+n]), hex=raw[at:at+n].hex())
              for name, (at, n) in FUNCTIONS.items()]
    return dict(schema="a7cr-slot1-native-menu-audit/1", source_sha256=AP_HASH,
                model="ILCE-7CR", firmware="2.01", slot=1, native_index=10,
                calls=[dict(at=at, target=FUNCTIONS[name][0], role=name) for at, name in edges.items()],
                model_pointers=pointers, guards=guards,
                source="Original A7CR menu setter and QAQLeonard v3.0.3 native synchronization sequence",
                evidence_type="static-disassembly", camera_executed=False,
                full_rtOS_or_ISP_verified=False, native_hardware_behavior_verified=False)


def header(report, *, read_only, expected_before, target, require_current_st):
    if type(read_only) is not bool or type(require_current_st) is not bool:
        raise ValueError("Explicit native mode booleans required")
    if read_only:
        if expected_before is not None or target is not None or require_current_st:
            raise ValueError("Read-only probe must contain no write target")
    elif any(type(x) is not int or not 0 <= x <= 11 for x in (expected_before, target)):
        raise ValueError("Writer needs bounded fresh native before-value and target")
    lines = [f"#define WRITE_ALLOWED {int(not read_only)}",
             f"#define EXPECTED_BEFORE {expected_before if expected_before is not None else 0}",
             f"#define TARGET_BASE {target if target is not None else 0}",
             f"#define REQUIRE_CURRENT_ST {int(require_current_st)}",
             "struct Guard {u64 at;u32 size;const u8 *data;};"]
    entries = []
    for index, g in enumerate(report["guards"]):
        lines.append(f"static const u8 guard_{index}[]={{"+",".join(map(str, bytes.fromhex(g['hex'])))+"};")
        entries.append(f"{{{g['offset']}UL,{g['bytes']},guard_{index}}}")
    lines.append("static const struct Guard guards[]={"+",".join(entries)+"};")
    lines.append(f"static const u32 guard_count={len(entries)};")
    return "\n".join(lines)+"\n"


def prepare(output, *, read_only=True, expected_before=None, target=None, require_current_st=False):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Use a new immutable native-worker directory")
    raw = AP_PATH.read_bytes()
    report = audit(raw)
    text = header(report, read_only=read_only, expected_before=expected_before,
                  target=target, require_current_st=require_current_st)
    source = (ROOT / "device/native/single_slot_bindings.c").read_text()
    # Reuse the already-reviewed maps-only proc reader, with no numeric CII model probe.
    probe = ROOT / "private/runtime-diagnostic/probe.c"
    existing = json.loads((probe.parent/"runtime.private.json").read_text())
    if not existing["simulation_passed"] or sha(probe.read_bytes()) != PROC_HASH:
        raise ValueError("Base proc reader simulation has not passed")
    output.mkdir(parents=True, exist_ok=False)
    (output/"probe.c").write_bytes(probe.read_bytes())
    spec = compile_worker(output, "slot1-probe" if read_only else "slot1-sync", source, text)
    result = dict(schema="a7cr-slot1-native-worker/1", audit=report, worker=spec,
                  read_only=read_only, expected_before=expected_before, target=target,
                  require_current_st=require_current_st, selected_slot=1, selected_native_index=10,
                  source_sha256=AP_HASH, proc_reader_sha256=sha(probe.read_bytes()),
                  camera_executed=False, simulation_passed=False,
                  firmware_resources_mount_or_wbi_written=False,
                  persistent_settings_may_change=not read_only)
    (output/"worker.private.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


def decode(raw, *, read_only, expected_before=None, target=None, require_current_st=False):
    if len(raw) != 272:
        raise ValueError("Incomplete slot 1 native report")
    magic,version,mode,status,pid,base,current,after_current,changed,reserved = struct.unpack_from("<8sIIqqQIIII", raw)
    if magic != b"A7CSB001" or version != 1 or mode != int(not read_only) or reserved or pid <= 0 or base <= 0:
        raise ValueError("Wrong native report identity/mode")
    if status:
        raise ValueError(f"Slot 1 native report failed: {status}")
    before=list(struct.unpack_from("<18I",raw,56));after=list(struct.unpack_from("<18I",raw,128))
    boot=raw[200:264].split(b"\0",1)[0].decode("ascii")
    if raw[264:] != bytes(8) or current != after_current:
        raise ValueError("Native current selection or reserved bytes changed")
    if any(x > 11 for x in before+after):
        raise ValueError("Unexpected native base enum")
    expected=before[:]
    if not read_only:
        if before[10] != expected_before:
            raise ValueError("Native before value changed after preparation")
        expected[10]=target
        if require_current_st and current != 0:
            raise ValueError("Owner must select global ST before recovery")
    if after != expected or changed != ((1<<10) if not read_only and before[10] != target else 0):
        raise ValueError("Native sync changed an unselected base or missed its target")
    import re
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", boot) is None:
        raise ValueError("Native boot identity missing")
    return dict(read_only=read_only, current=current, after_current=after_current,
                before_bases=before, after_bases=after, changed_mask=changed,
                pid=pid, base=base, boot_id=boot, only_slot1_may_change=True)


if __name__ == "__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args=p.parse_args()
    result=prepare(args.output)
    print(json.dumps({"worker":result["worker"],"read_only":True,"camera_executed":False},indent=2))
