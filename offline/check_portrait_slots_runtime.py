"""Actual portrait worker instruction tests with synthetic native contracts.

No USB/camera access. The original Sony callees are stubbed at their guarded
entries. This proves bounded worker behavior, not actual RTOS/persistence/ISP.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_X0,UC_ARM64_REG_X8,UC_ARM64_REG_X30
from check_native_workers import Machine,REGS,mount_text
import portrait_slots_runtime as runtime

ROOT=runtime.ROOT
APP_BASE=0x50000000
BACKING=APP_BASE+0x8F00000
CONTEXT=0xA7C00023
RESULT='/tmp/jiritsu/'+runtime.RESULT_NAME
RESULTS={RESULT,'/tmp/jiritsu/'+runtime.PROC_RESULT_NAME}
NORMAL=['context_enter','lock','values_getter','info_getter','current_getter','record','notify','unlock','context_leave','notice']
LOCKED_REJECT=['context_enter','lock','values_getter','info_getter','current_getter','unlock','context_leave']


def proc_files():
    with runtime.AP_PATH.open('rb') as stream:
        elf=ELFFile(stream);maps=[]
        for segment in elf.iter_segments():
            if segment['p_type']!='PT_LOAD':continue
            start=APP_BASE+(segment['p_vaddr']&~4095)
            stop=APP_BASE+((segment['p_vaddr']+segment['p_filesz']+4095)&~4095)
            flags='r-xp' if segment['p_flags']&1 else 'rw-p'
            maps.append(f"{start:x}-{stop:x} {flags} {segment['p_offset']&~4095:08x} 00:01 100 /usr/lib/appFw.so\n")
    return {'/proc/self/maps':''.join(maps).encode(),'/proc/self/cmdline':b'appFw\0',
            '/proc/mounts':mount_text(),'/proc/self/mem':b'',
            '/proc/sys/kernel/random/boot_id':b'12345678-1234-1234-1234-123456789abc\n',
            '/tmp/jiritsu/libJit.so':b'synthetic-loader'}


class PortraitMachine(Machine):
    def __init__(self,manifest,*,before=None,current=0,backing=True,guard_bad=False,short=False,
                 bad_enum=False,base_race=False,current_race=False,foreign_notice=None,uid=0):
        self.manifest=manifest;self.index=manifest.get('selected_native_index')
        self.short_mem=short;self.backing=backing;self.base_race=base_race;self.current_race=current_race
        self.foreign_notice=foreign_notice;self.native_calls=[];self.process_writes=[]
        self.locked=False;self.context_pointer=None;self.lock_pointer=None
        self.initial=[0,1,2,3,4,5,6,7,8,9,0,5,6,7,4,8,10,11]
        if before is not None:self.initial[self.index]=before
        if bad_enum:self.initial[8]=99
        self.initial_current=current;files=proc_files();self.saved_files=deepcopy(files)
        blob=(ROOT/manifest['worker']['file']).read_bytes()
        if len(blob)!=manifest['worker']['bytes'] or runtime.sha(blob)!=manifest['worker']['sha256']:
            raise ValueError('Actual compiled portrait worker changed')
        super().__init__(blob,files,uid=uid)
        pages=set()
        def put(at,raw):
            for page in range(at&~4095,(at+len(raw)+4095)&~4095,4096):
                if page not in pages:self.uc.mem_map(page,4096);pages.add(page)
            self.uc.mem_write(at,raw)
        for guard in manifest['audit']['guards']:put(APP_BASE+guard['offset'],bytes.fromhex(guard['hex']))
        put(APP_BASE+runtime.CURRENT_VA,struct.pack('<I',current))
        put(APP_BASE+runtime.VALUES_VA,struct.pack('<18I',*self.initial))
        put(APP_BASE+runtime.INFO_VA,bytes(40*18));put(BACKING,b'\0'*16)
        if self.index is not None:
            put(BACKING,struct.pack('<I',self.initial[self.index]))
            put(APP_BASE+runtime.INFO_VA+40*self.index+8,struct.pack('<Q',BACKING if backing else 0))
        if guard_bad:
            at=APP_BASE+manifest['audit']['guards'][0]['offset'];old=bytes(self.uc.mem_read(at,1))[0]
            self.uc.mem_write(at,bytes([old^1]))
        self.entries={APP_BASE+offset:name for name,(offset,_) in runtime.FUNCTIONS.items()}
        self.uc.hook_add(UC_HOOK_CODE,self.stub)
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.watch,begin=APP_BASE,end=APP_BASE+0x9000000)

    def watch(self,uc,access,at,size,value,unused):self.process_writes.append((at,size,value))
    def values(self):return list(struct.unpack('<18I',bytes(self.uc.mem_read(APP_BASE+runtime.VALUES_VA,72))))
    def current(self):return struct.unpack('<I',bytes(self.uc.mem_read(APP_BASE+runtime.CURRENT_VA,4)))[0]

    def stub(self,uc,address,size,unused):
        name=self.entries.get(address)
        if name is None:return
        if self.manifest['read_only']:raise ValueError('Read-only probe called native setter')
        args=[uc.reg_read(r) for r in REGS];self.native_calls.append(name)
        if name=='context_enter':
            if self.context_pointer is not None:raise ValueError('Nested native context')
            self.context_pointer=args[0];uc.mem_write(args[0],struct.pack('<2Q',0,CONTEXT))
        elif name=='lock':
            if self.locked or self.context_pointer is None:raise ValueError('Native lock order differs')
            self.locked=True;self.lock_pointer=args[0]
            if self.base_race:uc.mem_write(APP_BASE+runtime.VALUES_VA+4*self.index,struct.pack('<I',(self.manifest['expected_before']+1)%12))
            if self.current_race:uc.mem_write(APP_BASE+runtime.CURRENT_VA,struct.pack('<I',10))
        elif name in ('values_getter','info_getter','current_getter'):
            if not self.locked:raise ValueError('Native pointer obtained outside lock')
            offset={'values_getter':runtime.VALUES_VA,'info_getter':runtime.INFO_VA,'current_getter':runtime.CURRENT_VA}[name]
            uc.reg_write(UC_ARM64_REG_X0,APP_BASE+offset)
        elif name=='record':
            pointer=BACKING if self.backing else APP_BASE+runtime.VALUES_VA+4*self.index
            if not self.locked or args[:3]!=[CONTEXT,0x14E9+self.index,pointer] or args[4]!=4:
                raise ValueError('Record called for wrong slot/attribute/backing')
            if struct.unpack('<I',bytes(uc.mem_read(args[3],4)))[0]!=self.manifest['target']:
                raise ValueError('Recorded native target differs')
        elif name=='notify':
            if not self.locked or args[0]!=0x14E9+self.index:raise ValueError('Wrong selected notice')
            if self.foreign_notice=='cc':uc.mem_write(APP_BASE+runtime.VALUES_VA+40,struct.pack('<I',9))
            if self.foreign_notice=='slot4':uc.mem_write(APP_BASE+runtime.VALUES_VA+52,struct.pack('<I',2))
            if self.foreign_notice=='current':uc.mem_write(APP_BASE+runtime.CURRENT_VA,struct.pack('<I',3))
        elif name=='unlock':
            if not self.locked or args[0]!=self.lock_pointer:raise ValueError('Unbalanced unlock')
            self.locked=False
        elif name=='context_leave':
            if self.locked or args[0]!=self.context_pointer:raise ValueError('Unbalanced context')
            self.context_pointer=None
        elif name=='notice':
            if self.locked or self.context_pointer is not None or args[0]!=0x14E9:raise ValueError('Wrong final notice')
        else:raise ValueError('Unexpected native function call: '+name)
        uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))

    def syscall(self,uc,interrupt,unused):
        number=uc.reg_read(UC_ARM64_REG_X8);args=[uc.reg_read(r) for r in REGS]
        if number==67 and args[0] in self.fds and self.fds[args[0]][0]=='/proc/self/mem':
            self.calls.append(number);n=max(0,args[2]-1) if self.short_mem else args[2]
            if n:uc.mem_write(args[1],bytes(uc.mem_read(args[3],n)))
            return self.result(n)
        if number in (64,68) and args[0] in self.fds and self.fds[args[0]][0] not in RESULTS:
            raise ValueError('Worker wrote unowned persistent/process file')
        return super().syscall(uc,interrupt,unused)


def execute(manifest,name,status=0,native=None,**options):
    if manifest['source_sha256']!=runtime.AP_HASH or manifest['proc_reader_sha256']!=runtime.PROC_HASH:
        raise ValueError('Worker source/proc identity differs')
    machine=PortraitMachine(manifest,**options);machine.run();raw=bytes(machine.files[RESULT])
    actual=struct.unpack_from('<q',raw,16)[0]
    if actual!=status:raise ValueError(f'{name}: status {actual}, expected {status}')
    accepted=True
    try:runtime.decode(raw,read_only=manifest['read_only'],selected_slot=manifest['selected_slot'],
        expected_before=manifest['expected_before'],target=manifest['target'],require_current_st=manifest['require_current_st'])
    except ValueError:accepted=False
    if accepted!=(status==0):raise ValueError('Host decode accepted failed native result')
    if machine.program_writes or machine.sysfs_writes or 40 in machine.calls or 68 in machine.calls:
        raise ValueError('Worker mutated persistent/program/mount state')
    for path,value in machine.saved_files.items():
        if path!='/tmp/jiritsu/libJit.so' and bytes(machine.files[path])!=value:raise ValueError('Input file changed')
    if set(machine.files)-set(machine.saved_files)!=RESULTS or machine.locked or machine.context_pointer is not None:
        raise ValueError('Unowned result or leaked native lock/context')
    if native is not None and machine.native_calls!=native:raise ValueError('Native call sequence differs: '+str(machine.native_calls))
    if manifest['read_only']:
        if machine.native_calls or machine.process_writes or machine.values()!=machine.initial or machine.current()!=machine.initial_current:
            raise ValueError('Read-only probe changed native memory')
    else:
        allowed={APP_BASE+runtime.VALUES_VA+4*machine.index}
        if machine.backing:allowed.add(BACKING)
        if any(at not in allowed or n!=4 for at,n,_ in machine.process_writes):raise ValueError('Actual worker wrote an unselected model address')
        if status==0:
            wanted=machine.initial[:];wanted[machine.index]=manifest['target']
            if machine.values()!=wanted or machine.current()!=machine.initial_current:
                raise ValueError('Successful writer changed CC/unselected/current state')
        if status==-116 and (machine.process_writes or 'record' in machine.native_calls):
            raise ValueError('CAS/global-ST refusal occurred after native mutation')
    return {'case':name,'passed':True,'native_status':actual,'native_calls':machine.native_calls,
            'model_write_addresses':[hex(a) for a,_,_ in machine.process_writes],
            'native_functions_stubbed':True,'host_accepted':accepted}


def validate_artifact(path):
    path=Path(path).resolve();manifest=json.loads(path.read_text());rows=[]
    common=(('guard-mismatch',{'guard_bad':True},-84),('non-root',{'uid':501},-13),
            ('short-read',{'short':True},-5),('bad-enum',{'bad_enum':True},-22),('bad-current-enum',{'current':99},-22))
    if manifest['read_only']:
        rows.append(execute(manifest,'readonly-full18',native=[]))
        rows += [execute(manifest,'readonly-'+name,status,native=[],**opts) for name,opts,status in common]
    else:
        before,target=manifest['expected_before'],manifest['target'];calls=[] if before==target else NORMAL
        rows.append(execute(manifest,'selected-transition',before=before,native=calls))
        rows.append(execute(manifest,'selected-no-backing',before=before,backing=False,native=calls))
        rows.append(execute(manifest,'before-mismatch',-116,before=(before+1)%12,native=[]))
        rows.append(execute(manifest,'requires-global-st',-116,before=before,current=10,native=[]))
        rows += [execute(manifest,name,status,before=before,native=[],**opts) for name,opts,status in common]
        if before!=target:
            rows.append(execute(manifest,'locked-base-race',-116,before=before,base_race=True,native=LOCKED_REJECT))
            rows.append(execute(manifest,'locked-current-race',-116,before=before,current_race=True,native=LOCKED_REJECT))
            for foreign in ('cc','slot4','current'):
                rows.append(execute(manifest,'reject-notice-change-'+foreign,-84,before=before,foreign_notice=foreign,native=NORMAL))
    result={'schema':'a7cr-portrait-native-simulation/1','passed':True,'worker_sha256':manifest['worker']['sha256'],
            'selected_slot':manifest['selected_slot'],'cases':rows,'actual_compiled_worker_executed':True,
            'camera_accessed':False,'hardware_or_persistence_verified':False,
            'limits':['Sony callees are stub contracts; actual RTOS/notification/persistence/ISP is not emulated.',
                      'A post-notification error can follow the selected write; no rollback or safe replay is claimed.']}
    evidence=path.parent/'simulation.private.json';evidence.write_text(json.dumps(result,indent=2)+'\n')
    manifest.update(simulation_passed=True,simulation_cases=len(rows),simulation_report=str(evidence.relative_to(ROOT)),
                    simulation_report_sha256=runtime.sha(evidence.read_bytes()))
    path.write_text(json.dumps(manifest,indent=2)+'\n')
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('manifest',type=Path)
    args=parser.parse_args();result=validate_artifact(args.manifest)
    print(json.dumps({'passed':result['passed'],'cases':len(result['cases']),'camera_accessed':False},indent=2))
