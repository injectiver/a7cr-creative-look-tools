"""Controlled CP bootstrap replay. Cache/MMU operations are modeled, no USB."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_CPSR
from inspect_sources import ROOT, save_json


def replay(cp):
    base = 0x108000
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.mem_map(0x100000, 0x3000000)
    u.mem_map(0x3e40000, 0x10000)
    u.mem_write(base, cp)
    # A sentinel in the proposed table range detects source/lifetime overlap.
    sentinel = bytes((i*37+11)%256 for i in range(7322))
    u.mem_write(0x110000, sentinel)
    main = struct.unpack_from("<I", cp, 0x20000)[0]
    events = {"instructions": 0, "modeled_cache_mmu_calls": 0, "table_overwrites": [], "main": main}
    def code(cpu, at, size, _):
        events["instructions"] += 1
        if at == main:
            events["reached_main"] = True
            cpu.emu_stop()
        elif at == 0x108728:
            # Cache invalidation / MMU enable sequence; the identity-backed
            # byte replay does not claim hardware translation verification.
            events["modeled_cache_mmu_calls"] += 1
            cpu.reg_write(UC_ARM_REG_PC, at+4)
    def write(cpu, access, at, size, value, _):
        if at < 0x110000+7322 and at+size > 0x110000:
            events["table_overwrites"].append([at, size])
    u.hook_add(UC_HOOK_CODE, code)
    u.hook_add(UC_HOOK_MEM_WRITE, write)
    u.reg_write(UC_ARM_REG_CPSR, 0xd3)
    u.reg_write(UC_ARM_REG_SP, 0x300f000)
    u.emu_start(0x108398, 0, count=1000000)
    events["final_pc"] = u.reg_read(UC_ARM_REG_PC)
    events["table_bytes_preserved"] = bytes(u.mem_read(0x110000, 7322)) == sentinel
    events["ok"] = bool(events.get("reached_main") and events["table_bytes_preserved"] and not events["table_overwrites"])
    return events


if __name__ == "__main__":
    cp = (ROOT/"private/components/ILCE-7CR_2.01/cpapp-b.bin").read_bytes()
    result = replay(cp)
    result.update(schema="a7cr-cp-bootstrap-replay/1", device_access=False,
                  hardware_cache_mmu_emulated=False, whole_file_preload_proof_separate=True)
    save_json(ROOT/"private/offline/lut-port/bootstrap.private.json", result)
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        raise ValueError("Controlled bootstrap did not preserve proposed tables")
