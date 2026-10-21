"""Run upstream-derived workers against a synthetic syscall/filesystem model.

No USB, host mounts or host syscalls are executed by the emulated code. These
tests do not represent a camera boot, real filesystem timing or power loss.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_INTR, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_CPACR_EL1

from build_native_workers import OUT, ROOT, compile_worker, manifest_header, source
from inspect_sources import save_json

AP = "/usr/lib/appFw.so"
CP = "/cp/cpapp-b.bin"
REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Machine:
    def __init__(self, blob, files, *, uid=0, readonly=True, fail_write=None, short_reads=False):
        self.files = {key: bytearray(value) for key, value in files.items()}
        self.fds = {}
        self.uid, self.readonly, self.fail_write = uid, readonly, fail_write
        self.short_reads = short_reads
        self.failed = False
        self.calls, self.program_writes, self.sysfs_writes = [], [], []
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.base, self.halt = 0x10000000, 0x08000000
        elf = ELFFile(io.BytesIO(blob))
        loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
        end = max(segment["p_vaddr"]+segment["p_memsz"] for segment in loads)
        self.uc.mem_map(self.base, (end+4095) & ~4095)
        for segment in loads:
            self.uc.mem_write(self.base+segment["p_vaddr"], segment.data())
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_RELA":
                for relocation in section.iter_relocations():
                    if relocation["r_info_type"] != 1027:
                        raise ValueError("Unexpected relocation")
                    self.uc.mem_write(self.base+relocation["r_offset"], struct.pack("<Q", self.base+relocation["r_addend"]))
        self.init = self.base+next(symbol["st_value"] for symbol in elf.get_section_by_name(".dynsym").iter_symbols() if symbol.name == "_init")
        self.uc.mem_map(0x20000000, 0x20000)
        self.uc.mem_map(self.halt, 0x1000)
        self.uc.reg_write(UC_ARM64_REG_SP, 0x2001F000)
        self.uc.reg_write(UC_ARM64_REG_X30, self.halt)
        self.uc.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
        self.uc.hook_add(UC_HOOK_INTR, self.syscall)

    def cstring(self, address):
        raw = bytearray()
        while True:
            value = bytes(self.uc.mem_read(address+len(raw), 1))
            if value == b"\0":
                return raw.decode()
            raw += value
            if len(raw) > 512:
                raise ValueError("Unbounded emulated path")

    def result(self, number):
        self.uc.reg_write(UC_ARM64_REG_X0, number & ((1 << 64)-1))

    def syscall(self, uc, interrupt, unused):
        if interrupt != 2:
            raise ValueError(f"Unexpected emulated interrupt {interrupt}")
        number = uc.reg_read(UC_ARM64_REG_X8)
        a = [uc.reg_read(reg) for reg in REGS]
        self.calls.append(number)
        if number == 56:
            path, flags = self.cstring(a[1]), a[2]
            if path not in self.files and not flags & 0x40:
                return self.result(-2)
            if path == AP and flags & 3 and self.readonly:
                return self.result(-30)
            if flags & 0x200:
                self.files[path] = bytearray()
            self.files.setdefault(path, bytearray())
            fd = max([2]+list(self.fds))+1
            self.fds[fd] = [path, 0]
            return self.result(fd)
        if number == 57:
            self.fds.pop(a[0], None)
            return self.result(0)
        if number == 35:
            path = self.cstring(a[1])
            if path != "/tmp/jiritsu/libJit.so":
                raise ValueError("Worker unlinked an unowned path")
            if path not in self.files:
                return self.result(-2)
            del self.files[path]
            return self.result(0)
        if number in (63, 67):
            path, position = self.fds[a[0]]
            offset = a[3] if number == 67 else position
            amount = min(a[2], 23) if self.short_reads and number == 67 else a[2]
            raw = bytes(self.files[path][offset:offset+amount])
            if number == 63:
                self.fds[a[0]][1] += len(raw)
            if path == "/dev/kmsg" and not raw:
                return self.result(-11)
            if raw:
                uc.mem_write(a[1], raw)
            return self.result(len(raw))
        if number in (64, 68):
            path, position = self.fds[a[0]]
            raw = bytes(uc.mem_read(a[1], a[2]))
            offset = a[3] if number == 68 else position
            if path in (AP, CP):
                if number != 68:
                    raise ValueError("Unexpected sequential program write")
                if self.fail_write == path and not self.failed:
                    self.failed = True
                    # Model a failed syscall after one accepted partial write.
                    self.files[path][offset:offset+2] = raw[:2]
                    return self.result(-5)
                self.program_writes.append((path, offset, len(raw)))
            if path.startswith("/sys/"):
                self.sysfs_writes.append((path, raw))
                if path == "/sys/power/image_drop" and raw == b"1":
                    self.files["/dev/kmsg"] += b"6,1,1;dropped wbi\n"
                elif path == "/sys/power/image_mode" and raw == b"0":
                    self.files[path] = bytearray(b"0\n")
                else:
                    raise ValueError("Unexpected sysfs mutation")
            else:
                current = self.files[path]
                if offset+len(raw) > len(current):
                    current += bytes(offset+len(raw)-len(current))
                current[offset:offset+len(raw)] = raw
            if number == 64:
                self.fds[a[0]][1] += len(raw)
            return self.result(len(raw))
        if number == 80:
            path = self.fds[a[0]][0]
            data = bytearray(128)
            struct.pack_into("<QQIIIIQQqIIQ", data, 0, 9, 100 if path == AP else 101,
                             0o100644, 1, 0, 0, 0, 0, len(self.files[path]), 4096, 0, 8)
            uc.mem_write(a[1], bytes(data))
            return self.result(0)
        if number == 40:
            if self.cstring(a[1]) != "/usr":
                raise ValueError("Unexpected mount target")
            self.readonly = bool(a[3] & 1)
            self.files["/proc/mounts"] = bytearray(mount_text(self.readonly))
            return self.result(0)
        if number == 62:
            path = self.fds[a[0]][0]
            if path != "/dev/kmsg" or a[2] != 2:
                raise ValueError("Unexpected seek")
            self.fds[a[0]][1] = len(self.files[path])
            return self.result(len(self.files[path]))
        if number == 82:
            return self.result(0)
        if number == 175:
            return self.result(self.uid)
        if number == 172:
            return self.result(77)
        raise ValueError(f"Unexpected native syscall {number}")

    def run(self):
        # /proc/mounts is synthesized from the current emulated mount state.
        self.uc.emu_start(self.init, self.halt, count=30_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC) != self.halt:
            raise ValueError("Worker did not return within instruction budget")
        if self.fds:
            raise ValueError("Worker leaked file descriptors")


def mount_text(readonly=True):
    return b"/dev/nflasha15 /usr ext2 "+(b"ro" if readonly else b"rw")+b",relatime 0 0\n/dev/nflasha8 /cp vfat rw,relatime 0 0\n"


def program_files(ap, cp, mode):
    return {AP: ap, CP: cp, "/proc/mounts": mount_text(), "/tmp/jiritsu/libJit.so": b"synthetic-worker",
            "/tmp/jiritsu/a7cr.install.request": struct.pack("<8sII", b"A7INS001", mode, 0)}


def program_report(machine):
    raw = machine.files["/tmp/jiritsu/a7cr.install.result"]
    if len(raw) != 240:
        raise ValueError("Native program report is truncated")
    values = struct.unpack("<8s4I7q4Q64s64s", raw)
    if values[0] != b"A7IRP001" or values[1] != 1:
        raise ValueError("Wrong native program report ABI")
    return {"mode": values[2], "phase": values[3], "writes": values[4], "status": values[5],
            "rollback": values[6], "readonly": values[8], "cleanup": values[9]}


def main():
    folder = OUT / "synthetic-tests"
    ap, cp = bytes((i*3) % 256 for i in range(1024)), bytes((i*7+4) % 256 for i in range(1536))
    after_ap, after_cp = bytearray(ap), bytearray(cp)
    after_ap[32:40], after_cp[64:72] = b"APCHANGE", b"CPCHANGE"
    final = bytes(after_ap), bytes(after_cp)
    windows = [{"offset": at, "bytes": 8, "chip": chip, "before_hex": old[at:at+8].hex(), "after_hex": new[at:at+8].hex()}
               for chip, at, old, new in ((0, 32, ap, final[0]), (1, 64, cp, final[1]))]
    header = manifest_header([sha(ap), sha(cp)], [sha(x) for x in final], [len(ap), len(cp)], windows)
    compiled = {"check": compile_worker(folder / "check", "check", source("program", True), header),
                "program": compile_worker(folder / "program", "program", source("program"), header),
                "wbi-check": compile_worker(folder / "wbi-check", "wbi-check", source("wbi", True)),
                "wbi": compile_worker(folder / "wbi", "wbi", source("wbi"))}
    blobs = {key: (ROOT / value["file"]).read_bytes() for key, value in compiled.items()}
    results = []
    for name, worker, mode, initial, options, success in (
        ("read-only-full-check", "check", 0, (ap, cp), {}, True),
        ("check-rejects-install", "check", 1, (ap, cp), {}, False),
        ("check-rejects-restore", "check", 2, final, {}, False),
        ("reject-non-root", "check", 0, (ap, cp), {"uid": 501}, False),
        ("reject-corrupt-source", "check", 0, (ap[:-1]+b"x", cp), {}, False),
        ("reject-truncated-source", "check", 0, (ap[:-1], cp), {}, False),
        ("short-read-reassembly", "check", 0, (ap, cp), {"short_reads": True}, True),
        ("synthetic-install", "program", 1, (ap, cp), {}, True),
        ("synthetic-restore", "program", 2, final, {}, True),
        ("partial-write-auto-rollback", "program", 1, (ap, cp), {"fail_write": CP}, False),
    ):
        machine = Machine(blobs[worker], program_files(*initial, mode), **options)
        machine.run(); report = program_report(machine)
        if (report["status"] == 0) != success:
            raise ValueError(f"Unexpected outcome for {name}: {report}")
        if worker == "check":
            if machine.program_writes or 40 in machine.calls or 68 in machine.calls:
                raise ValueError("Check-only worker attempted program/mount mutation")
            if (bytes(machine.files[AP]), bytes(machine.files[CP])) != initial:
                raise ValueError("Check-only worker changed programs")
        elif success:
            expected = final if mode == 1 else (ap, cp)
            if (bytes(machine.files[AP]), bytes(machine.files[CP])) != expected or not machine.readonly:
                raise ValueError(f"Program transition mismatch for {name}")
        elif name == "partial-write-auto-rollback":
            if (bytes(machine.files[AP]), bytes(machine.files[CP])) != (ap, cp) or report["rollback"] != 0 or not machine.readonly:
                raise ValueError("Synthetic partial-write recovery failed")
        results.append({"case": name, "passed": True, "report": report})
    # Exercise the two dependency stages and their inverse, including an AP
    # failure after CP succeeded. The same generator produces the real workers.
    cp_only = (ap, final[1])
    stage_headers = {
        "cp": manifest_header([sha(ap), sha(cp)], [sha(x) for x in cp_only], [len(ap), len(cp)], [windows[1]]),
        "ap": manifest_header([sha(x) for x in cp_only], [sha(x) for x in final], [len(ap), len(cp)], [windows[0]]),
    }
    stage_blobs = {}
    for stage, stage_header in stage_headers.items():
        spec = compile_worker(folder / (stage+"-stage"), stage+"-stage", source("program"), stage_header)
        stage_blobs[stage] = (ROOT / spec["file"]).read_bytes()
    for name, stage, mode, initial, expected, options, success in (
        ("cp-stage-install-preserves-ap", "cp", 1, (ap, cp), cp_only, {}, True),
        ("ap-stage-install-preserves-cp", "ap", 1, cp_only, final, {}, True),
        ("ap-stage-restore-preserves-cp", "ap", 2, final, cp_only, {}, True),
        ("cp-stage-restore-preserves-ap", "cp", 2, cp_only, (ap, cp), {}, True),
        ("ap-failure-keeps-previous-cp-stage", "ap", 1, cp_only, cp_only, {"fail_write": AP}, False),
        ("ap-stage-rejects-missing-cp-stage", "ap", 1, (ap, cp), (ap, cp), {}, False),
    ):
        machine = Machine(stage_blobs[stage], program_files(*initial, mode), **options)
        machine.run(); report = program_report(machine)
        if ((report["status"] == 0) != success or not machine.readonly
                or (bytes(machine.files[AP]), bytes(machine.files[CP])) != expected):
            raise ValueError("Two-stage transition/inverse differs: " + name)
        if any(path != (CP if stage == "cp" else AP) for path, _, _ in machine.program_writes):
            raise ValueError("Worker wrote a program outside its dependency stage")
        results.append({"case": name, "passed": True, "report": report})
    for name, worker, mode, initial_mode, success in (
        ("wbi-inspect-only", "wbi-check", 0, b"2\n", True),
        ("wbi-check-rejects-drop", "wbi-check", 1, b"2\n", False),
        ("wbi-rejects-wrong-start", "wbi", 1, b"0\n", False),
        ("wbi-drop-then-mode0", "wbi", 1, b"2\n", True),
    ):
        files = {"/tmp/jiritsu/libJit.so": b"synthetic-worker",
                 "/tmp/jiritsu/a7cr.wbi.request": struct.pack("<8sII", b"A7WBI001", mode, 0),
                 "/sys/power/image_mode": initial_mode, "/sys/power/image_dev": b"*wbi4\n",
                 "/sys/power/image_drop": b"", "/dev/kmsg": b""}
        machine = Machine(blobs[worker], files);machine.run()
        values = struct.unpack("<8sII9q16s16s32s32sII", machine.files["/tmp/jiritsu/a7cr.wbi.result"])
        if (values[3] == 0) != success:
            raise ValueError(f"Unexpected WBI outcome: {name}: {values[3]}")
        expected_writes = [("/sys/power/image_drop", b"1"), ("/sys/power/image_mode", b"0")] if name == "wbi-drop-then-mode0" else []
        if machine.sysfs_writes != expected_writes:
            raise ValueError("WBI inspection mutated state or mutation order differs")
        results.append({"case": name, "passed": True, "status": values[3]})
    record = {"schema": "a7cr-native-syscall-simulation/1", "device_access": False,
              "actual_camera_boot_simulated": False, "results": results,
              "limitations": ["Synthetic files/syscalls; not actual RTOS/kernel/filesystem timing", "No power-loss or physical recovery guarantee"]}
    save_json(OUT / "simulation.private.json", record)
    manifest = json.loads((OUT / "workers.private.json").read_text())
    manifest["native_simulation_passed"] = True
    manifest["synthetic_case_count"] = len(results)
    save_json(OUT / "workers.private.json", manifest)
    print(json.dumps({"passed_cases": len(results), "device_access": False,
                      "camera_preflight_passed": manifest["camera_preflight_passed"]}, indent=2))


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--runtime-only"]:
        from check_runtime_diagnostic import run
        run(Machine)
    elif sys.argv[1:]:
        raise ValueError("Unsupported offline simulation argument")
    else:
        main()
