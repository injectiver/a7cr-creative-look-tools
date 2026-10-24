"""Incremental CC-to-portrait loaded-reader tests with actual changed spans.

Adapted from check_runtime_diagnostic.py; no camera/USB access.
"""
from __future__ import annotations

from copy import deepcopy
import json
import sys
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_X8

from build_runtime_diagnostic import ROOT, OUT
from inspect_sources import save_json
sys.path.insert(0, str(ROOT / "device"))
from diagnose_fl23 import decode_probe, decode_runtime


def run(Machine,manifest_path=None,program_paths=None):
    manifest_path = manifest_path or OUT / "runtime.private.json"
    manifest = json.loads(manifest_path.read_text())
    blob = (ROOT / manifest["worker"]["file"]).read_bytes()
    spans = manifest["spans"]
    directory = ROOT / "private/install/fl23/payload"
    program_paths=program_paths or {d:directory/(d+"-AP.private.bin") for d in ("original","candidate")}
    regions = {}
    for direction in ("original", "candidate"):
        with program_paths[direction].open("rb") as stream:
            items = {}
            for span in spans:
                stream.seek(span["offset"])
                items[span["offset"]] = stream.read(span["bytes"])
            regions[direction] = items
    class Slices:
        def __init__(self, regions):
            self.regions = regions
        def __getitem__(self, key):
            return self.regions[key.start][:key.stop-key.start]
    package = SimpleNamespace(programs={key: {"AP": Slices(data)} for key, data in regions.items()})
    base = 0x50000000
    with program_paths['candidate'].open("rb") as stream:
        elf = ELFFile(stream)
        maps = []
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            start = base+(seg["p_vaddr"] & ~4095)
            stop = base+((seg["p_vaddr"]+seg["p_filesz"]+4095) & ~4095)
            offset = seg["p_offset"] & ~4095
            flags = "r-xp" if seg["p_flags"] & 1 else "rw-p"
            maps.append(f"{start:x}-{stop:x} {flags} {offset:08x} 00:01 100 /usr/lib/appFw.so\n")
    from check_native_workers import REGS, mount_text
    class SparseMachine(Machine):
        def __init__(self, files, live, *, short=False, **options):
            self.live, self.short_sparse = live, short
            super().__init__(blob, files, **options)
        def syscall(self, uc, interrupt, unused):
            number = uc.reg_read(UC_ARM64_REG_X8)
            a = [uc.reg_read(reg) for reg in REGS]
            if number == 67 and a[0] in self.fds:
                path = self.fds[a[0]][0]
                if path in ("/proc/self/mem", "/usr/lib/appFw.so"):
                    self.calls.append(number)
                    for index, span in enumerate(spans):
                        origin = base+span["virtual_offset"] if path == "/proc/self/mem" else span["offset"]
                        if origin <= a[3] < origin+span["bytes"]:
                            offset = a[3]-origin
                            data = self.live[index] if path == "/proc/self/mem" else regions["candidate"][span["offset"]]
                            n = min(a[2], len(data)-offset, 5 if self.short_sparse else a[2])
                            uc.mem_write(a[1], data[offset:offset+n])
                            return self.result(n)
                    return self.result(-14)
            return super().syscall(uc, interrupt, unused)
    changed = [i for i, span in enumerate(spans)
               if regions["original"][span["offset"]] != regions["candidate"][span["offset"]]]
    if not changed:
        raise ValueError("Incremental reader test needs actually different source/candidate spans")
    results = []
    for name, options in (
        ("all-loaded-candidate", {}),
        ("detect-stale-loaded-original", {"live": "original"}),
        ("detect-mixed-loaded-span", {"mixed": True}),
        ("reject-missing-data-mapping", {"missing": True}),
        ("reject-wrong-file-offset-mapping", {"wrong-offset": True}),
        ("reject-non-root-runtime", {"uid": 501}),
        ("reassemble-short-runtime-reads", {"short": True}),
    ):
        live = [regions[options.get("live", "candidate")][span["offset"]] for span in spans]
        if options.get("mixed"):
            live[changed[0]] = regions["original"][spans[changed[0]]["offset"]]
        current_maps = maps[:1] if options.get("missing") else maps.copy()
        if options.get("wrong-offset"):
            fields = current_maps[1].split(" ")
            fields[2] = f"{int(fields[2],16)+4096:08x}"
            current_maps[1] = " ".join(fields)
        files = {"/proc/self/maps": "".join(current_maps).encode(), "/proc/self/cmdline": b"appFw\0",
                 "/proc/mounts": mount_text(), "/proc/self/mem": b"", "/usr/lib/appFw.so": b"",
                 "/sys/power/image_mode": b"2\n", "/sys/power/image_dev": b"*wbi4\n",
                 "/proc/uptime": b"31.00 122.00\n",
                 "/proc/sys/kernel/random/boot_id": b"12345678-1234-1234-1234-123456789abc\n",
                 "/tmp/jiritsu/libJit.so": b"synthetic-loader-file"}
        saved = deepcopy(files)
        machine = SparseMachine(files, live, uid=options.get("uid", 0), short=options.get("short", False))
        machine.run()
        if machine.program_writes or machine.sysfs_writes or 40 in machine.calls or 68 in machine.calls:
            raise ValueError("Runtime diagnostic mutated protected state")
        for path, data in saved.items():
            if path != "/tmp/jiritsu/libJit.so" and bytes(machine.files[path]) != data:
                raise ValueError("Runtime diagnostic changed an input file")
        if set(machine.files)-set(saved) != {"/tmp/jiritsu/a7cr.diag.probe.result", "/tmp/jiritsu/a7cr.diag.runtime.result"}:
            raise ValueError("Runtime diagnostic wrote an unowned file")
        raw = bytes(machine.files["/tmp/jiritsu/a7cr.diag.runtime.result"])
        if options.get("uid"):
            try:
                decode_runtime(raw, spans, package)
            except ValueError:
                results.append({"case": name, "passed": True}); continue
            raise ValueError("Non-root diagnostic was incorrectly accepted")
        report = decode_runtime(raw, spans, package)
        probe = decode_probe(bytes(machine.files["/tmp/jiritsu/a7cr.diag.probe.result"]))
        expect_all = not any(options.get(key) for key in ("live", "mixed", "missing", "wrong-offset"))
        if report["all_loaded_ap_spans_match_candidate"] != expect_all or report["pid"] != probe["pid"]:
            raise ValueError("Loaded-state classification differs: " + name)
        if options.get("live") and not all(
                s['loaded_state']==('original' if regions['original'][span['offset']]!=regions['candidate'][span['offset']] else 'candidate')
                for s,span in zip(report['spans'],spans)):
            raise ValueError("Stale original loaded spans were not identified")
        if (options.get("missing") or options.get("wrong-offset")) and report["native_status"] != -14:
            raise ValueError("Unbacked/mistranslated mapping accepted")
        results.append({"case": name, "passed": True, "native_status": report["native_status"]})
    save_json(manifest_path.parent / "simulation.private.json", {"schema": "a7cr-portrait-loaded-reader-simulation/1", "results": results,
                                                "changed_span_indices": changed, "mixed_case_changed_index": changed[0],
                                                "device_access": False, "physical_camera_boot_simulated": False})
    manifest["simulation_passed"] = True
    manifest["simulation_cases"] = len(results)
    save_json(manifest_path, manifest)
    print(json.dumps({"runtime_readonly_cases": len(results), "device_access": False, "persistent_camera_writes": False}, indent=2))
