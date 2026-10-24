"""Execute the actual slot-1 workers with synthetic proc data and native stubs.

No USB or camera access. Calls into Sony AP functions are replaced with audited
stub contracts; this checks worker instruction/control flow, not Sony RTOS,
locking semantics, persistence callbacks, preview, or camera hardware behavior.
"""
from __future__ import annotations

from copy import deepcopy
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X8, UC_ARM64_REG_X30

from check_native_workers import Machine, REGS, mount_text
import single_slot_runtime as runtime


ROOT = runtime.ROOT
OUT = ROOT / "private/single-slot-runtime"
APP_BASE = 0x50000000
CONTEXT = 0xA7C00001
BACKING = APP_BASE + 0x8F00000
RESULT = "/tmp/jiritsu/a7cr.slot1.bindings.result"
OWNED_RESULTS = {RESULT, "/tmp/jiritsu/a7cr.diag.probe.result"}
BOOT = b"12345678-1234-1234-1234-123456789abc\n"


def proc_files():
    with runtime.AP_PATH.open("rb") as stream:
        elf = ELFFile(stream)
        maps = []
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD": continue
            start = APP_BASE + (segment["p_vaddr"] & ~4095)
            end = APP_BASE + ((segment["p_vaddr"] + segment["p_filesz"] + 4095) & ~4095)
            flags = "r-xp" if segment["p_flags"] & 1 else "rw-p"
            maps.append(f"{start:x}-{end:x} {flags} {segment['p_offset'] & ~4095:08x} 00:01 100 /usr/lib/appFw.so\n")
    return {"/proc/self/maps":"".join(maps).encode(), "/proc/self/cmdline":b"appFw\0",
            "/proc/mounts":mount_text(), "/proc/self/mem":b"",
            "/proc/sys/kernel/random/boot_id":BOOT,
            "/tmp/jiritsu/libJit.so":b"synthetic-loader-file"}


class SlotMachine(Machine):
    """Sparse AP address space plus declared contracts for native menu calls."""
    def __init__(self, blob, manifest, *, before=5, current=0, backing=True,
                 guard_mismatch=False, short_mem=False, bad_enum=False,
                 lock_race=False, current_race=False, other_base_changed=False,
                 current_changed=False, uid=0):
        self.manifest = manifest
        self.short_mem, self.lock_race, self.current_race = short_mem, lock_race, current_race
        self.other_base_changed, self.current_changed = other_base_changed, current_changed
        self.native_calls, self.native_arguments, self.process_writes = [], [], []
        self.locked = False
        self.context_pointer = self.lock_pointer = None
        self.has_backing = backing
        self.initial = [i % 12 for i in range(18)]
        self.initial[10] = before
        if bad_enum: self.initial[4] = 99
        self.initial_current = current
        files = proc_files()
        self.saved_files = deepcopy(files)
        super().__init__(blob,files,uid=uid)
        pages = set()
        def put(address, raw):
            for page in range(address & ~4095, (address + len(raw) + 4095) & ~4095, 4096):
                if page not in pages:
                    self.uc.mem_map(page,4096); pages.add(page)
            self.uc.mem_write(address,raw)
        for guard in manifest["audit"]["guards"]:
            put(APP_BASE+guard["offset"],bytes.fromhex(guard["hex"]))
        put(APP_BASE+runtime.CURRENT_VA,struct.pack("<I",current))
        put(APP_BASE+runtime.VALUES_VA,struct.pack("<18I",*self.initial))
        put(APP_BASE+runtime.INFO_VA,bytes(40*18))
        put(BACKING,struct.pack("<I",before))
        put(APP_BASE+runtime.INFO_VA+40*10+8,struct.pack("<Q",BACKING if backing else 0))
        if guard_mismatch:
            first=manifest["audit"]["guards"][0]
            at=APP_BASE+first["offset"]
            self.uc.mem_write(at,bytes([bytes(self.uc.mem_read(at,1))[0]^1]))
        self.native_addresses = {APP_BASE+offset:name for name,(offset,_) in runtime.FUNCTIONS.items()}
        self.uc.hook_add(UC_HOOK_CODE,self.native_stub)
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.watch_process_write,
                         begin=APP_BASE,end=APP_BASE+0x9000000)

    def watch_process_write(self,uc,access,address,size,value,unused):
        self.process_writes.append((address,size,value))

    def values(self):
        return list(struct.unpack("<18I",bytes(self.uc.mem_read(APP_BASE+runtime.VALUES_VA,72))))

    def current(self):
        return struct.unpack("<I",bytes(self.uc.mem_read(APP_BASE+runtime.CURRENT_VA,4)))[0]

    def native_stub(self,uc,address,size,unused):
        name=self.native_addresses.get(address)
        if name is None:return
        args=[uc.reg_read(reg) for reg in REGS]
        self.native_calls.append(name); self.native_arguments.append((name,args))
        if self.manifest["read_only"]:
            raise ValueError("Read-only worker called a native mutation function")
        if name=="context_enter":
            if self.context_pointer is not None:raise ValueError("Nested native context")
            self.context_pointer=args[0]
            uc.mem_write(args[0],struct.pack("<2Q",0,CONTEXT))
        elif name=="lock":
            if self.context_pointer is None or self.locked:raise ValueError("Bad native lock order")
            self.locked=True;self.lock_pointer=args[0]
            if self.lock_race:
                uc.mem_write(APP_BASE+runtime.VALUES_VA+40,struct.pack("<I",(self.manifest["expected_before"]+1)%12))
            if self.current_race:
                uc.mem_write(APP_BASE+runtime.CURRENT_VA,struct.pack("<I",10))
        elif name=="values_getter":
            if not self.locked:raise ValueError("Model read outside native lock")
            uc.reg_write(UC_ARM64_REG_X0,APP_BASE+runtime.VALUES_VA)
        elif name=="info_getter":
            if not self.locked:raise ValueError("Info read outside native lock")
            uc.reg_write(UC_ARM64_REG_X0,APP_BASE+runtime.INFO_VA)
        elif name=="current_getter":
            if not self.locked:raise ValueError("Current read outside native lock")
            uc.reg_write(UC_ARM64_REG_X0,APP_BASE+runtime.CURRENT_VA)
        elif name=="record":
            expected_pointer=BACKING if self.has_backing else APP_BASE+runtime.VALUES_VA+40
            if not self.locked or args[:3]!=[CONTEXT,0x14F3,expected_pointer] or args[4]!=4:
                raise ValueError("Wrong slot/attribute/record call contract")
            value=struct.unpack("<I",bytes(uc.mem_read(args[3],4)))[0]
            if value!=self.manifest["target"]:raise ValueError("Recorded wrong target base")
        elif name=="notify":
            if not self.locked or args[0]!=0x14F3:raise ValueError("Wrong native notice order/attribute")
            if self.other_base_changed:
                uc.mem_write(APP_BASE+runtime.VALUES_VA+44,struct.pack("<I",9))
            if self.current_changed:
                uc.mem_write(APP_BASE+runtime.CURRENT_VA,struct.pack("<I",3))
        elif name=="unlock":
            if not self.locked or args[0]!=self.lock_pointer:raise ValueError("Unbalanced native unlock")
            self.locked=False
        elif name=="context_leave":
            if self.locked or args[0]!=self.context_pointer:raise ValueError("Unbalanced native context")
            self.context_pointer=None
        elif name=="notice":
            if self.locked or self.context_pointer is not None or args[0]!=0x14E9:
                raise ValueError("Wrong final Creative Look notice")
        else:
            raise ValueError("Worker called an unapproved native function: "+name)
        uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))

    def syscall(self,uc,interrupt,unused):
        number=uc.reg_read(UC_ARM64_REG_X8)
        args=[uc.reg_read(reg) for reg in REGS]
        if number==67 and args[0] in self.fds and self.fds[args[0]][0]=="/proc/self/mem":
            self.calls.append(number)
            amount=max(0,args[2]-1) if self.short_mem else args[2]
            data=bytes(uc.mem_read(args[3],amount))
            if data:uc.mem_write(args[1],data)
            return self.result(amount)
        if number in (64,68) and args[0] in self.fds:
            path=self.fds[args[0]][0]
            if path not in OWNED_RESULTS:raise ValueError("Worker wrote an unowned persistent/process file")
        return super().syscall(uc,interrupt,unused)


def execute_case(manifest,name,*,expect_status=0,expected_native=None,**options):
    if manifest["source_sha256"]!=runtime.AP_HASH or manifest["proc_reader_sha256"]!=runtime.PROC_HASH:
        raise ValueError("Worker manifest is not bound to the reviewed AP/proc reader")
    blob=(ROOT/manifest["worker"]["file"]).read_bytes()
    if len(blob)!=manifest["worker"]["bytes"] or runtime.sha(blob)!=manifest["worker"]["sha256"]:
        raise ValueError("Native worker changed")
    machine=SlotMachine(blob,manifest,**options)
    machine.run()
    raw=bytes(machine.files[RESULT])
    status=struct.unpack_from("<q",raw,16)[0]
    if status!=expect_status:raise ValueError(f"{name}: native status {status}, expected {expect_status}")
    accepted=True
    try:
        decoded=runtime.decode(raw,read_only=manifest["read_only"],expected_before=manifest["expected_before"],
            target=manifest["target"],require_current_st=manifest["require_current_st"])
    except ValueError:
        accepted=False;decoded=None
    if accepted!=(expect_status==0):raise ValueError("Host decoder did not reject native failure: "+name)
    if machine.program_writes or machine.sysfs_writes or 40 in machine.calls or 68 in machine.calls:
        raise ValueError("Worker changed programs/sysfs/mounts/process through syscalls")
    for path,raw_input in machine.saved_files.items():
        if path!="/tmp/jiritsu/libJit.so" and bytes(machine.files[path])!=raw_input:
            raise ValueError("Worker changed input file: "+path)
    if set(machine.files)-set(machine.saved_files)!=OWNED_RESULTS:
        raise ValueError("Worker created an unowned file")
    if machine.locked or machine.context_pointer is not None:
        raise ValueError("Native lock/context leaked")
    if expected_native is not None and machine.native_calls!=expected_native:
        raise ValueError(f"{name}: wrong native sequence {machine.native_calls}")
    if manifest["read_only"] and (machine.native_calls or machine.process_writes or machine.values()!=machine.initial or machine.current()!=machine.initial_current):
        raise ValueError("Read-only worker mutated the native AP model")
    if not manifest["read_only"]:
        permitted={APP_BASE+runtime.VALUES_VA+40}
        if machine.has_backing:permitted.add(BACKING)
        if any(address not in permitted or size!=4 for address,size,_ in machine.process_writes):
            raise ValueError("Native writer instruction touched an unowned model location")
        if expect_status==0:
            expected=machine.initial[:];expected[10]=manifest["target"]
            if machine.values()!=expected or machine.current()!=machine.initial_current:
                raise ValueError("Successful native setter modified unselected state")
        if expect_status==-116 and (machine.process_writes or "record" in machine.native_calls):
            raise ValueError("CAS/global ST rejection happened after a model write")
    return {"case":name,"passed":True,"native_status":status,"native_calls":machine.native_calls,
            "model_write_addresses":[hex(a) for a,_,_ in machine.process_writes],
            "host_accepted":accepted,"sony_function_calls_stubbed":True}


def _load_or_prepare(path,**options):
    manifest=Path(path)/"worker.private.json"
    if manifest.exists():
        result=json.loads(manifest.read_text())
        if any(result[key]!=value for key,value in options.items()):raise ValueError("Keep different existing simulation fixture")
        source=(ROOT/"device/native/single_slot_bindings.c").read_text()
        if result["worker"]["source_sha256"]!=runtime.sha(source.encode()):
            raise ValueError("Existing fixture was compiled from different native source")
        return result
    return runtime.prepare(path,**options)


def validate_artifact(manifest_path):
    """Execute and certify one independently compiled catalog artifact.

    Supports every bounded before/target pair, including no-op workers. Source
    identity and actual binary are checked by execute_case; no live transport.
    """
    manifest_path=Path(manifest_path)
    manifest=json.loads(manifest_path.read_text())
    rows=[]
    common=(("guard-mismatch",{"guard_mismatch":True},-84),
            ("non-root",{"uid":501},-13),("short-memory-read",{"short_mem":True},-5),
            ("bad-native-enum",{"bad_enum":True},-22))
    if manifest["read_only"]:
        rows.append(execute_case(manifest,"readonly-correct-model",expected_native=[]))
        rows.extend(execute_case(manifest,"readonly-"+name,expect_status=status,expected_native=[],**options)
                    for name,options,status in common)
    else:
        before,target=manifest["expected_before"],manifest["target"]
        normal=["context_enter","lock","values_getter","info_getter","current_getter", "record","notify","unlock","context_leave","notice"]
        reject=["context_enter","lock","values_getter","info_getter","current_getter","unlock","context_leave"]
        expected=[] if before==target else normal
        rows.append(execute_case(manifest,"catalog-correct-transition",before=before,expected_native=expected))
        rows.append(execute_case(manifest,"catalog-no-backing",before=before,backing=False,expected_native=expected))
        rows.append(execute_case(manifest,"catalog-before-mismatch",before=(before+1)%12,
                                 expect_status=-116,expected_native=[]))
        rows.extend(execute_case(manifest,"catalog-"+name,before=before,expect_status=status,expected_native=[],**options)
                    for name,options,status in common)
        if manifest["require_current_st"]:
            rows.append(execute_case(manifest,"catalog-owner-global-st-required",before=before,current=10,
                                     expect_status=-116,expected_native=[]))
        if before!=target:
            rows.append(execute_case(manifest,"catalog-before-race-at-lock",before=before,lock_race=True,
                                     expect_status=-116,expected_native=reject))
            if manifest["require_current_st"]:
                rows.append(execute_case(manifest,"catalog-current-race-at-lock",before=before,current_race=True,
                                         expect_status=-116,expected_native=reject))
            rows.append(execute_case(manifest,"catalog-unselected-notice-change",before=before,
                                     other_base_changed=True,expect_status=-84,expected_native=normal))
            rows.append(execute_case(manifest,"catalog-current-notice-change",before=before,
                                     current_changed=True,expect_status=-84,expected_native=normal))
    result={"schema":"a7cr-slot1-catalog-worker-simulation/1","worker_sha256":manifest["worker"]["sha256"],
            "passed":True,"cases":rows,"camera_accessed":False,"native_functions_stubbed":True,
            "hardware_or_persistence_verified":False}
    (manifest_path.parent/"simulation.private.json").write_text(json.dumps(result,indent=2)+"\n")
    manifest["simulation_passed"]=True;manifest["simulation_cases"]=len(rows)
    manifest["simulation_limit"]="Actual worker instructions and synthetic proc/native stubs; not RTOS, persistence or hardware."
    manifest_path.write_text(json.dumps(manifest,indent=2)+"\n")
    return result


def run(probe_path=None):
    probe_path=Path(probe_path or OUT/"probe-v2/worker.private.json")
    probe=json.loads(probe_path.read_text())
    source_hash=runtime.sha((ROOT/"device/native/single_slot_bindings.c").read_bytes())
    writer_path=OUT/("simulation-writer-"+source_hash[:12])
    noop_path=OUT/("simulation-noop-"+source_hash[:12])
    restore_path=OUT/("simulation-restore-"+source_hash[:12])
    writer=_load_or_prepare(writer_path,read_only=False,expected_before=5,target=0,require_current_st=True)
    noop=_load_or_prepare(noop_path,read_only=False,expected_before=0,target=0,require_current_st=False)
    restore=_load_or_prepare(restore_path,read_only=False,expected_before=0,target=9,require_current_st=True)
    normal=["context_enter","lock","values_getter","info_getter","current_getter","record","notify","unlock","context_leave","notice"]
    locked_reject=["context_enter","lock","values_getter","info_getter","current_getter","unlock","context_leave"]
    rows=[]
    for name,options,status in (
        ("readonly-correct-model",{},0),
        ("readonly-guard-mismatch",{"guard_mismatch":True},-84),
        ("readonly-non-root",{"uid":501},-13),
        ("readonly-short-memory-read",{"short_mem":True},-5),
        ("readonly-bad-native-enum",{"bad_enum":True},-22),
    ):rows.append(execute_case(probe,name,expect_status=status,expected_native=[],**options))
    for name,options,status,calls in (
        ("writer-slot1-backed",{},0,normal),
        ("writer-slot1-no-backing",{"backing":False},0,normal),
        ("writer-before-value-mismatch",{"before":4},-116,[]),
        ("writer-needs-owner-global-st",{"current":10},-116,[]),
        ("writer-before-race-at-lock",{"lock_race":True},-116,locked_reject),
        ("writer-current-race-at-lock",{"current_race":True},-116,locked_reject),
        ("writer-guard-mismatch",{"guard_mismatch":True},-84,[]),
        ("writer-non-root",{"uid":501},-13,[]),
        ("writer-short-memory-read",{"short_mem":True},-5,[]),
        ("writer-bad-native-enum",{"bad_enum":True},-22,[]),
        ("writer-detects-unselected-notification-change",{"other_base_changed":True},-84,normal),
        ("writer-detects-current-notification-change",{"current_changed":True},-84,normal),
    ):rows.append(execute_case(writer,name,expect_status=status,expected_native=calls,**options))
    rows.append(execute_case(noop,"writer-aligned-st-no-op",before=0,current=10,expected_native=[]))
    rows.append(execute_case(restore,"restore-original-native-base",before=0,expected_native=normal))
    rows.append(execute_case(restore,"restore-native-base-requires-global-st",before=0,current=10,
                             expect_status=-116,expected_native=[]))
    result={"schema":"a7cr-slot1-runtime-simulation/1","passed":True,"cases":rows,
        "camera_accessed":False,"persistent_camera_writes":False,"actual_compiled_worker_executed":True,
        "limits":["Native Sony functions replaced with stub contracts; their hardware, RTOS and persistence behavior is not emulated.",
                  "Synthetic proc mappings and model arrays; no live AP or camera USB.",
                  "An error after notification may follow the selected model write; no rollback or replay is claimed."]}
    for path,manifest in ((probe_path,probe),(writer_path/"worker.private.json",writer),
                          (noop_path/"worker.private.json",noop),(restore_path/"worker.private.json",restore)):
        if manifest["read_only"]:
            selected=[r for r in rows if r["case"].startswith("readonly")]
        elif manifest["target"]==9:
            selected=[r for r in rows if r["case"].startswith("restore")]
        elif manifest["expected_before"]==0:
            selected=[r for r in rows if r["case"]=="writer-aligned-st-no-op"]
        else:
            selected=[r for r in rows if r["case"].startswith("writer") and r["case"]!="writer-aligned-st-no-op"]
        manifest["simulation_passed"]=True
        manifest["simulation_cases"]=len(selected)
        manifest["simulation_limit"]="Actual worker instructions with synthetic proc and native function stubs; not camera hardware verification."
        Path(path).write_text(json.dumps(manifest,indent=2)+"\n")
    (OUT/"runtime-simulation.private.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"native_worker_cases":len(rows),"passed":True,"camera_accessed":False},indent=2))
    return result


if __name__=="__main__":run()
