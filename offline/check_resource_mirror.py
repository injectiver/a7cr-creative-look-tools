"""Replay the actual temp-mirror ELF against synthetic files; no camera I/O."""
from __future__ import annotations
import json
import struct
from unicorn.arm64_const import UC_ARM64_REG_PC
from check_native_workers import Machine,REGS,UC_ARM64_REG_X8
from build_resource_mirror import ROOT,OUT,FILE
from inspect_sources import save_json
from build_native_workers import sha
import sys
sys.path.insert(0,str(ROOT/'device'))
from install_six_luts import Package

SOURCE='/usr/share/app/'+FILE
DATA='/tmp/jiritsu/a7cr.six.boundary.data'
RESULT='/tmp/jiritsu/a7cr.six.boundary.result'


class MirrorMachine(Machine):
    def __init__(self,*args,fault=None,**kwargs):
        super().__init__(*args,**kwargs);self.fault=fault
    def syscall(self,uc,interrupt,unused):
        n=uc.reg_read(UC_ARM64_REG_X8);a=[uc.reg_read(r) for r in REGS]
        if n==56:
            path=self.cstring(a[1]);flags=a[2]
            if path==SOURCE and flags&3:raise ValueError('Mirror opened source for write')
            if path in self.files and flags&0xc0==0xc0:return self.result(-17)
        if n==80 and self.fds[a[0]][0]==SOURCE:
            b=bytearray(128);struct.pack_into('<QQIIIIQQqIIQ',b,0,9,121,0o100644,1,
                1 if self.fault=='owner' else 57285,1000,0,0,len(self.files[SOURCE]),4096,0,8)
            uc.mem_write(a[1],bytes(b));return self.result(0)
        if n==64 and self.fds[a[0]][0] not in (DATA,RESULT):raise ValueError('Mirror wrote an unowned file')
        return super().syscall(uc,interrupt,unused)
    def run(self):
        self.uc.emu_start(self.init,self.halt,count=100_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC)!=self.halt or self.fds:raise ValueError('Mirror leaked fds or did not return')


def main():
    p=Package();m=json.loads((OUT/'mirror.private.json').read_text());blob=(ROOT/m['worker']['file']).read_bytes()
    if sha(blob)!=m['worker']['sha256']:raise ValueError('Mirror test input changed')
    rows=[]
    for name,raw,options,ok in [('native-resource',p.resources[FILE],{},True),('named-resource',p.named_resources[FILE],{},True),
        ('short-reads',p.named_resources[FILE],{'short_reads':True},True),
        ('wrong-source-owner',p.named_resources[FILE],{'fault':'owner'},False),
        ('non-root',p.named_resources[FILE],{'uid':501},False),
        ('corrupt-source',p.named_resources[FILE][:-1]+b'x',{},False),
        ('wrong-source-size',p.named_resources[FILE][:-4],{},False),
        ('existing-mirror',p.named_resources[FILE],{'existing':True},False)]:
        files={SOURCE:raw,'/tmp/jiritsu/libJit.so':b'module'}
        existing=options.pop('existing',False)
        if existing:files[DATA]=b'preserve this existing result'
        x=MirrorMachine(blob,files,**options);x.run();v=struct.unpack('<8sII4q2Q32s',x.files[RESULT])
        if v[0]!=b'A7CRM001' or (v[3]==0)!=ok:raise ValueError('Unexpected mirror result: '+name)
        if bytes(x.files[SOURCE])!=raw or x.program_writes or x.sysfs_writes or 40 in x.calls:
            raise ValueError('Mirror changed persistent source/mount state')
        if ok and (bytes(x.files[DATA])!=raw+b'\xa7' or v[-1]!=bytes.fromhex(sha(raw))):
            raise ValueError('Mirror copy/hash differs')
        if existing and x.files[DATA]!=files[DATA]:raise ValueError('Mirror overwrote a previous result')
        rows.append(dict(case=name,passed=True));print('Mirror: '+name+' passed',flush=True)
    m['simulation_passed']=True;m['simulation_cases']=len(rows)
    save_json(OUT/'simulation.private.json',dict(results=rows,device_access=False,persistent_source_writes=False))
    save_json(OUT/'mirror.private.json',m)
    print(json.dumps(dict(passed_cases=len(rows),camera_access=False)))


if __name__=='__main__':main()
