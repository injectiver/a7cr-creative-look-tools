"""Native syscall simulations for six-look window sizes and atomic names."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from unicorn.arm64_const import UC_ARM64_REG_PC
from check_native_workers import Machine,AP,CP,program_files,program_report,mount_text
from build_native_workers import ROOT,compile_worker,manifest_header,source,array,sha
from inspect_sources import save_json

JOB=ROOT/'private/lut-install/six-20261020-01'
OUT=JOB/'simulation'


class NameMachine(Machine):
    def __init__(self,*args,fault=None,**kwargs):
        super().__init__(*args,**kwargs);self.inodes={p:100+i for i,p in enumerate(self.files)}
        self.fault=fault;self.faulted=False;self.renames=0
    def syscall(self,uc,interrupt,unused):
        from check_native_workers import REGS,UC_ARM64_REG_X8
        n=uc.reg_read(UC_ARM64_REG_X8);a=[uc.reg_read(r) for r in REGS]
        if n==56:
            path=self.cstring(a[1]);flags=a[2]
            if path in self.files and flags&0xc0==0xc0:return self.result(-17)
            if path.startswith('/usr/share/app/') and flags&3 and self.readonly:return self.result(-30)
            if path not in self.inodes:self.inodes[path]=max([100,*self.inodes.values()])+1
            if path=='/usr/share/app':self.files.setdefault(path,bytearray())
        if n==80:
            path=self.fds[a[0]][0];data=bytearray(128)
            owned=path==AP or path.startswith('/usr/share/app/')
            ino=self.inodes[path]
            struct.pack_into('<QQIIIIQQqIIQ',data,0,9,ino,0o100644,
                sum(x==ino for x in self.inodes.values()),57285 if owned else 0,1000 if owned else 0,
                0,0,len(self.files[path]),4096,0,8)
            uc.mem_write(a[1],bytes(data));return self.result(0)
        if n in (52,55):return self.result(0)
        if n==37:
            old,new=self.cstring(a[1]),self.cstring(a[3])
            if new in self.files:return self.result(-17)
            if self.fault=='link' and not self.faulted:self.faulted=True;return self.result(-5)
            self.files[new]=self.files[old];self.inodes[new]=self.inodes[old];return self.result(0)
        if n==38:
            old,new=self.cstring(a[1]),self.cstring(a[3]);self.renames+=1
            if self.fault=='second-commit' and self.renames==2 and not self.faulted:
                self.faulted=True;return self.result(-5)
            self.files[new]=self.files.pop(old);self.inodes[new]=self.inodes.pop(old);return self.result(0)
        if n==35:
            path=self.cstring(a[1])
            if path!='/tmp/jiritsu/libJit.so' and not (path.startswith('/usr/share/app/.a7c2-lut-') and path.endswith(('.stage','.original'))):
                raise ValueError('Name worker unlinked an unowned path')
            if path not in self.files:return self.result(-2)
            del self.files[path];self.inodes.pop(path,None);return self.result(0)
        if n==64:
            path=self.fds[a[0]][0]
            if self.fault=='stage-write' and path.endswith('.stage') and not self.faulted:
                self.faulted=True;return self.result(-5)
        return super().syscall(uc,interrupt,unused)
    def run(self):
        self.uc.emu_start(self.init,self.halt,count=900_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC)!=self.halt or self.fds:
            raise ValueError('Native name worker did not return/close its descriptors')


def programs(m):
    before=[];after=[];windows=[]
    for chip,kind in enumerate(('AP','CP')):
        old=bytearray(20000);new=bytearray(old);at=256
        for w in m['programs'][kind]['windows']:
            a,b=bytes.fromhex(w['before_hex']),bytes.fromhex(w['after_hex']);n=len(a)
            old[at:at+n]=a;new[at:at+n]=b
            windows.append(dict(chip=chip,offset=at,bytes=n,before_hex=a.hex(),after_hex=b.hex()))
            at=(at+n+63)&~63
        before.append(bytes(old));after.append(bytes(new))
    workers={};initial=list(map(sha,before));final=list(map(sha,after));middle=[initial[0],final[1]]
    for name,a,b,rows,readonly in [('program_check',initial,final,windows,True),
            ('cp_stage',initial,middle,[w for w in windows if w['chip']==1],False),
            ('ap_stage',middle,final,[w for w in windows if w['chip']==0],False)]:
        text=source('program',readonly)
        if sha(text.encode())!=m['workers'][name]['source_sha256']:raise ValueError('Worker algorithm differs from installed-size fixture')
        spec=compile_worker(OUT/name,name,text,manifest_header(a,b,[len(x) for x in before],rows))
        workers[name]=(ROOT/spec['file']).read_bytes()
    cp_only=[before[0],after[1]];cases=[]
    for name,worker,mode,initial_state,expected,options,success in [
        ('read-only-exact-window-boundaries','program_check',0,before,before,{},True),
        ('read-only-rejects-write','program_check',1,before,before,{},False),
        ('cp-install-large-prefix','cp_stage',1,before,cp_only,{},True),
        ('cp-inverse-large-prefix','cp_stage',2,cp_only,before,{},True),
        ('ap-install-preserves-cp','ap_stage',1,cp_only,after,{},True),
        ('ap-inverse-preserves-cp','ap_stage',2,after,cp_only,{},True),
        ('cp-partial-write-rollback','cp_stage',1,before,before,{'fail_write':CP},False),
        ('ap-partial-write-rollback','ap_stage',1,cp_only,cp_only,{'fail_write':AP},False),
        ('short-reads','program_check',0,before,before,{'short_reads':True},True),
        ('ap-rejects-missing-cp-stage','ap_stage',1,before,before,{},False),
        ('read-only-non-root','program_check',0,before,before,{'uid':501},False)]:
        x=Machine(workers[worker],program_files(*initial_state,mode),**options);x.run();r=program_report(x)
        if (r['status']==0)!=success or [bytes(x.files[p]) for p in (AP,CP)]!=expected or not x.readonly:
            raise ValueError('Six-worker simulation failed: '+name)
        if worker=='program_check' and x.program_writes:raise ValueError('Check worker wrote a program')
        cases.append(dict(case=name,passed=True))
    print('Program transaction / inverse / boundary simulations passed: '+str(len(cases)),flush=True)
    return cases


def names():
    import sys,os
    sys.path.insert(0,str(ROOT/'research/repos/a7c2-fl23-research/src/looks'))
    from looktool import resources
    from looktool.nativebuild import compile_worker as compile_names
    labels=list(range(0x0200ab2c,0x0200ab32));names=['Classic Neg.','Classic Chrome','Nostalgic Neg.','Eterna','GR Positive Film','GR Negative Film']
    raw=(struct.pack('<8sHHI',b'uxc\x07\0\0\0\0',8,5,2860|(2860<<12))
         +b'\0\0'+b'\xff\xff'*2859+struct.pack('<I',0x1e00a000)+b'ST\0\0')
    target,plan=resources.rename(raw,dict(enumerate(names,1)),labels)
    ap=b'A'*4096;named_ap=b'B'*4096
    filenames=['string_english_horizontal.uxc','string_english_vertical.uxc','string_simplifiedchinese_horizontal.uxc']
    rows=['{'+json.dumps(n)+','+str(len(raw))+','+array(bytes.fromhex(sha(raw)))+','+array(bytes.fromhex(sha(target)))+'}' for n in filenames]
    lines=['static const struct Asset assets[]={'+','.join(rows)+'};','static const u32 asset_count=3;',
        'static const u32 after_sizes[]={'+','.join([str(len(target))]*3)+'};',
        'static const u32 old_counts[]={2860,2860,2860};',
        'static const u32 label_ids[]={'+','.join(map(str,labels))+'};',
        'static const unsigned short old_pointers[68][6]={{65535,65535,65535,65535,65535,65535},{65535,65535,65535,65535,65535,65535},{65535,65535,65535,65535,65535,65535}};',
        'static const u8 names[6][64]={'+','.join(array(x.encode()+b'\0') for x in names)+'};',
        'static const u32 selected_mask=63;','static const char backup_prefix[]="/usr/share/app/.a7c2-lut-simulation-";',
        'static const u32 original_uid=57285,original_gid=1000;','static const u64 ap_size=4096;',
        'static const u8 ap_plain_hash[32]='+array(bytes.fromhex(sha(ap)))+';',
        'static const u8 ap_named_hash[32]='+array(bytes.fromhex(sha(named_ap)))+';']
    folder=OUT/'names';folder.mkdir(parents=True,exist_ok=True)
    (folder/'names.private.h').write_text('\n'.join(lines))
    os.environ['A7C2_ZIG_CACHE']=str(ROOT/'private/native-workers/lut-zig-cache')
    compile_names(ROOT/'research/repos/a7c2-fl23-research/src/looks/native/names.c',folder/'names.private.h',folder/'names-stripped.so')
    blob=(folder/'names-stripped.so').read_bytes();cases=[]
    def initial(mode):
        files={AP:ap,'/proc/mounts':mount_text(),'/tmp/jiritsu/libJit.so':b'worker',
            '/tmp/jiritsu/a7c2.names.request':struct.pack('<8sII',b'A7NAM001',mode,0)}
        files.update({'/usr/share/app/'+n:raw for n in filenames});return files
    committed=None
    for name,mode,fault,success in [('read-only-names',0,None,True),('atomic-title-install',1,None,True),
        ('stage-write-failure',1,'stage-write',False),('hardlink-failure',1,'link',False),('second-commit-failure',1,'second-commit',False)]:
        x=NameMachine(blob,initial(mode),fault=fault);x.run()
        v=struct.unpack('<8s4I7q6I32s',x.files['/tmp/jiritsu/a7c2.names.result'])
        if v[0]!=b'A7NMR001' or (v[5]==0)!=success or not x.readonly:raise ValueError('Atomic title case failed: '+name)
        wanted=target if mode==1 and success else raw
        if any(bytes(x.files['/usr/share/app/'+n])!=wanted for n in filenames):raise ValueError('Atomic title contents differ')
        if not success and any('.a7c2-lut-' in p for p in x.files):raise ValueError('Failed name transaction leaked owned files')
        if name=='atomic-title-install':
            committed={p:bytes(b) for p,b in x.files.items()}
            if any(committed['/usr/share/app/.a7c2-lut-simulation-'+n+'.original']!=raw for n in filenames):
                raise ValueError('Old resource inode data was not retained')
        cases.append(dict(case=name,passed=True));print('Native names: '+name+' passed',flush=True)
    for name,mode,newap in [('title-inverse',2,ap),('title-inverse-after-backup-cleanup',2,ap),('post-reload-cleanup',3,named_ap)]:
        files=dict(committed);files[AP]=newap;files['/tmp/jiritsu/libJit.so']=b'worker'
        if name=='title-inverse-after-backup-cleanup':files={p:b for p,b in files.items() if not p.endswith('.original')}
        files['/tmp/jiritsu/a7c2.names.request']=struct.pack('<8sII',b'A7NAM001',mode,0)
        x=NameMachine(blob,files);x.run();v=struct.unpack('<8s4I7q6I32s',x.files['/tmp/jiritsu/a7c2.names.result'])
        if v[5] or not x.readonly:raise ValueError('Title inverse/cleanup failed')
        if any(bytes(x.files['/usr/share/app/'+n])!=(raw if mode==2 else target) for n in filenames):
            raise ValueError('Title inverse/cleanup changed wrong bytes')
        if mode==3 and any('.original' in p for p in x.files):raise ValueError('Title cleanup left backups')
        cases.append(dict(case=name,passed=True))
    return cases


def main():
    m=json.loads((JOB/'package.private.json').read_text());OUT.mkdir(parents=True,exist_ok=True)
    cases=programs(m)+names()
    result=dict(schema='a7cr-six-worker-simulation/1',device_access=False,cases=cases,passed=True,
        program_manifest_shapes_identical=True,name_fixture_count=3,real_names_count=68,
        limitation='Synthetic syscalls and three representative language files; not physical filesystem timing or power-loss recovery.')
    save_json(JOB/'native-simulation.private.json',result)
    m['native_worker_simulation_passed']=True
    save_json(JOB/'package.private.json',m)
    print(json.dumps(dict(passed_cases=len(cases),device_access=False),indent=2))


if __name__=='__main__':
    import sys
    if sys.argv[1:]==['--runtime-only']:
        from check_runtime_diagnostic import run
        from build_lut_candidate import INPUT,OUT as CANDIDATE
        run(Machine,JOB/'runtime/runtime.private.json',{
            'original':INPUT/'candidate-AP.private.bin',
            'candidate':CANDIDATE/'candidate-AP.private.bin'})
    elif sys.argv[1:]:raise ValueError('Unsupported offline test argument')
    else:main()
