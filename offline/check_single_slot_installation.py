"""Bounded offline transaction evidence for one exact prepared package.

Actual compiled package workers execute inside Unicorn against synthetic files.
Only bulk SHA routines are substituted by host hashlib oracles; binaries and
source are unchanged. A reduced-file fixture independently executes the native
hash/compare algorithm and exact window shapes without those oracles. This is
not hardware, RTOS, power-failure, native full-size hashing or USB validation.
"""
from __future__ import annotations

import argparse
import gc
import io
import json
import os
import subprocess
from pathlib import Path
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_PC

from check_native_workers import Machine, AP, CP, program_files, program_report, mount_text
from check_six_workers import NameMachine
import prepare_single_slot_installation as prep

ROOT=prep.ROOT


def _symbol(blob,name):
    elf=ELFFile(io.BytesIO(blob));table=elf.get_section_by_name('.symtab')
    matches=[row for row in table.iter_symbols() if row.name==name] if table else []
    if len(matches)!=1 or matches[0]['st_info']['type']!='STT_FUNC' or not 0<matches[0]['st_size']<8192:
        raise ValueError('Exact compiled hashing routine cannot be identified: '+name)
    row=matches[0];at,n=row['st_value'],row['st_size']
    for segment in elf.iter_segments():
        if segment['p_type']=='PT_LOAD' and segment['p_vaddr']<=at<at+n<=segment['p_vaddr']+segment['p_filesz']:
            raw=segment.data()[at-segment['p_vaddr']:at-segment['p_vaddr']+n]
            return {'symbol':name,'virtual_offset':at,'bytes':n,'sha256':prep.sha(raw)}
    raise ValueError('Hashing routine is outside a file-backed executable segment')


class ProgramOracleMachine(Machine):
    def __init__(self,blob,files,**options):
        self.oracle=_symbol(blob,'verify_hashes');self.oracle_calls=[]
        super().__init__(blob,files,**options)
        elf=ELFFile(io.BytesIO(blob));symbols={row.name:row for row in elf.get_section_by_name('.symtab').iter_symbols()}
        self.hash_objects={name:self.base+symbols[name]['st_value'] for name in ('original_hashes','final_hashes','file_sizes')}
        if symbols['original_hashes']['st_size']!=64 or symbols['final_hashes']['st_size']!=64 or symbols['file_sizes']['st_size']!=16:
            raise ValueError('Compiled program hash-array ABI differs')
        self.uc.hook_add(UC_HOOK_CODE,self.hash_oracle,begin=self.base+self.oracle['virtual_offset'],end=self.base+self.oracle['virtual_offset'])
    def hash_oracle(self,uc,address,size,unused):
        after,out=uc.reg_read(UC_ARM64_REG_X0),uc.reg_read(UC_ARM64_REG_X1)
        if after not in (0,1):raise ValueError('Unexpected verify_hashes mode')
        sizes=struct.unpack('<2Q',bytes(uc.mem_read(self.hash_objects['file_sizes'],16)))
        expected=bytes(uc.mem_read(self.hash_objects['final_hashes' if after else 'original_hashes'],64))
        status=0;digests=[]
        for chip,path in enumerate((AP,CP)):
            raw=self.files[path]
            if len(raw)!=sizes[chip]:status=-5 if len(raw)<sizes[chip] else -27;break
            digest=bytes.fromhex(prep.sha(raw));digests.append(digest.hex());uc.mem_write(out+32*chip,digest)
            if digest!=expected[32*chip:32*(chip+1)]:status=-84;break
        self.oracle_calls.append({'mode':after,'digests':digests,'status':status})
        self.result(status);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))


class NamesOracleMachine(NameMachine):
    def __init__(self,blob,files,*,metadata_blob=None,**options):
        self.oracle=_symbol(metadata_blob if metadata_blob is not None else blob,'hash_path');self.oracle_calls=[]
        super().__init__(blob,files,**options)
        self.uc.hook_add(UC_HOOK_CODE,self.hash_oracle,begin=self.base+self.oracle['virtual_offset'],end=self.base+self.oracle['virtual_offset'])
    def hash_oracle(self,uc,address,size,unused):
        path=self.cstring(uc.reg_read(UC_ARM64_REG_X0));n=uc.reg_read(UC_ARM64_REG_X1)
        out,stat=uc.reg_read(UC_ARM64_REG_X2),uc.reg_read(UC_ARM64_REG_X3)
        status=0
        if path not in self.files:status=-2
        elif len(self.files[path])!=n:status=-22
        elif path!=AP and not path.startswith('/usr/share/app/'):
            raise ValueError('Name hash oracle received an unowned path')
        else:
            raw=self.files[path];digest=bytes.fromhex(prep.sha(raw));uc.mem_write(out,digest)
            if stat:
                inode=self.inodes[path];record=bytearray(128)
                struct.pack_into('<QQIIIIQQqIIQ',record,0,9,inode,0o100644,
                    sum(other==inode for other in self.inodes.values()),57285,1000,0,0,len(raw),4096,0,8)
                uc.mem_write(stat,bytes(record))
        self.oracle_calls.append({'path':path,'bytes':n,'status':status})
        self.result(status);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))


def _worker_blob(spec):
    raw=(ROOT/spec['file']).read_bytes()
    if len(raw)!=spec['bytes'] or prep.sha(raw)!=spec['sha256']:
        raise ValueError('Prepared worker changed')
    return raw


def _programs(package):
    checkpoint=(ROOT/package['checkpoint'])
    original={kind:(checkpoint/'copy-a'/f'{kind}.bin').read_bytes() for kind in ('AP','CP')}
    candidate={kind:(ROOT/package['programs'][kind]['candidate_file']).read_bytes() for kind in ('AP','CP')}
    for kind in original:
        spec=package['programs'][kind]
        if prep.sha(original[kind])!=spec['source_sha256'] or prep.sha(candidate[kind])!=spec['candidate_sha256']:
            raise ValueError('Prepared program identity differs')
    return original,candidate


def check_programs(package,output):
    import check_six_workers
    previous=check_six_workers.OUT;check_six_workers.OUT=output/'reduced-programs'
    try:reduced=check_six_workers.programs(package)
    finally:check_six_workers.OUT=previous
    original,candidate=_programs(package)
    initial=[original[k] for k in ('AP','CP')];final=[candidate[k] for k in ('AP','CP')];middle=[initial[0],final[1]]
    rows=[];oracles={};worker_hashes={name:package['workers'][name]['sha256'] for name in ('program_check','cp_stage','ap_stage','installed_check')}
    for name,kind,mode,start,expected,options,success in (
        ('baseline-check','program_check',0,initial,initial,{},True),
        ('check-rejects-install','program_check',1,initial,initial,{},False),
        ('check-rejects-restore','program_check',2,final,final,{},False),
        ('cp-install','cp_stage',1,initial,middle,{},True),
        ('ap-install','ap_stage',1,middle,final,{},True),
        ('installed-check','installed_check',0,final,final,{},True),
        ('restore-ap-first','ap_stage',2,final,middle,{},True),
        ('restore-cp-second','cp_stage',2,middle,initial,{},True),
        ('cp-short-write-rolls-back','cp_stage',1,initial,initial,{'fail_write':CP},False),
        ('ap-short-write-rolls-back','ap_stage',1,middle,middle,{'fail_write':AP},False),
        ('cp-inverse-short-write-rolls-back','cp_stage',2,middle,middle,{'fail_write':CP},False),
        ('ap-inverse-short-write-rolls-back','ap_stage',2,final,final,{'fail_write':AP},False),
        ('reject-ap-before-cp','ap_stage',1,initial,initial,{},False),
        ('reject-non-root','program_check',0,initial,initial,{'uid':501},False),
        ('window-short-read-reassembly','program_check',0,initial,initial,{'short_reads':True},True),
    ):
        machine=ProgramOracleMachine(_worker_blob(package['workers'][kind]),program_files(*start,mode),**options)
        try:
            machine.run();report=program_report(machine)
            if (report['status']==0)!=success or [bytes(machine.files[p]) for p in (AP,CP)]!=expected or not machine.readonly:
                raise ValueError('Exact-size program transaction differed: '+name)
            if kind in ('program_check','installed_check') and (machine.program_writes or 40 in machine.calls):
                raise ValueError('Read-only package worker attempted a persistent program/mount change')
            oracles[kind]=machine.oracle
            rows.append({'case':name,'passed':True,'report':report,'native_program_writes':len(machine.program_writes),'host_sha_oracle_calls':len(machine.oracle_calls)})
        finally:
            del machine;gc.collect()
    bad=[initial[0][:-1]+bytes([initial[0][-1]^1]),initial[1]]
    machine=ProgramOracleMachine(_worker_blob(package['workers']['program_check']),program_files(*bad,0))
    try:
        machine.run();report=program_report(machine)
        if report['status']!=-84 or machine.program_writes or 40 in machine.calls:
            raise ValueError('Wrong full source digest was not rejected before writes')
        rows.append({'case':'wrong-full-source-digest','passed':True,'report':report})
    finally:del machine;gc.collect()
    result={'schema':'a7cr-slot1-program-transaction-simulation/1','passed':True,'worker_sha256':worker_hashes,
        'actual_full_size_worker_cases':rows,'native_hash_algorithm_reduced_fixture_cases':reduced,
        'hash_oracle_routines':oracles,'camera_accessed':False,'hardware_or_power_failure_verified':False,
        'limits':['Actual package binaries and full-size files; verify_hashes alone is replaced in Unicorn by hashlib digest+compiled-array equality oracle.',
                  'Native windows, write/rollback order, syscall model, report and host full-byte result comparisons remain active.',
                  'Native hashing/equality and exact window shapes execute independently on reduced files; full-size native SHA loops are not executed.',
                  'Synthetic filesystem/syscalls; not physical timing, actual USB, RTOS or power loss.']}
    path=output/'programs.private.json';prep._private_json(path,result)
    return path,result


def _name_metadata(package,output,blob):
    """Recover symbols with a companion whose allocated sections are identical."""
    from looktool.nativebuild import zig_command,ROOT as upstream
    source=upstream/'src/looks/native/names.c'
    header=Path(package['names_build']['path']).parent/'names.private.h'
    build=package['names_build']
    if (prep.sha(source.read_bytes())!=build['native_source_sha256']
            or prep.sha(header.read_bytes())!=build['manifest_sha256']):
        raise ValueError('Exact native names source/header changed')
    destination=output/'names-symbols.so'
    command=zig_command()+['cc','-target','aarch64-linux-gnu','-shared','-fPIC','-O2',
        '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-nostdlib','-g0','-Wl,--no-undefined','-Wl,-Bsymbolic','-Wl,-z,noexecstack',
        '-I',str(upstream/'src/fl23/native'),'-I',str(header.parent),
        '-DPATCH_MANIFEST="'+header.resolve().as_posix()+'"','-o',str(destination),str(source)]
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'symbols-global'),ZIG_LOCAL_CACHE_DIR=str(output/'symbols-local'))
    subprocess.run(command,env=env,check=True,capture_output=True,text=True,timeout=180)
    metadata=destination.read_bytes()
    def allocated(raw):
        elf=ELFFile(io.BytesIO(raw))
        return {section.name:(section['sh_addr'],section['sh_size'],section['sh_flags'],section['sh_type'],
                    None if section['sh_type']=='SHT_NOBITS' else section.data())
                for section in elf.iter_sections() if section['sh_flags']&2}
    if allocated(blob)!=allocated(metadata):
        raise ValueError('Unstripped names metadata companion differs in allocated sections/layout')
    evidence={'actual_worker_sha256':prep.sha(blob),'metadata_companion_sha256':prep.sha(metadata),
              'allocated_sections_and_layout_identical':True,'actual_worker_unchanged':True,
              'companion_build_difference':'Only -Wl,--strip-debug omitted; same original source/header/optimization/target'}
    return metadata,evidence


def check_names(package,output):
    from looktool import nameworker,resources
    checkpoint=ROOT/package['checkpoint']
    originals={name:(checkpoint/'copy-a/resources'/name).read_bytes() for name in package['resources']}
    targets={name:(ROOT/spec['target_file']).read_bytes() for name,spec in package['resources'].items()}
    original_ap=(checkpoint/'copy-a/AP.bin').read_bytes()
    target_ap=(ROOT/package['programs']['AP']['candidate_file']).read_bytes()
    blob=_worker_blob(package['workers']['names_stage']);build=package['names_build'];rows=[]
    metadata,metadata_proof=_name_metadata(package,output,blob)
    for row in build['files']:
        if resources.inverse(targets[row['file']],row['inverse'])!=originals[row['file']]:
            raise ValueError('Complete 68-resource source inverse differs')
    def initial(mode):
        result={AP:original_ap,'/proc/mounts':mount_text(),'/tmp/jiritsu/libJit.so':b'synthetic-worker',
                '/tmp/jiritsu/a7c2.names.request':struct.pack('<8sII',b'A7NAM001',mode,0)}
        result.update({'/usr/share/app/'+name:raw for name,raw in originals.items()})
        return result
    committed=None;oracles=[]
    for name,mode,fault,success in (
        ('names-readonly-all68',0,None,True),('names-install-all68',1,None,True),
        ('names-stage-write-rollback',1,'stage-write',False),('names-link-failure-rollback',1,'link',False),
        ('names-second-commit-rollback',1,'second-commit',False)):
        machine=NamesOracleMachine(blob,initial(mode),metadata_blob=metadata,fault=fault)
        try:
            machine.run();raw=bytes(machine.files['/tmp/jiritsu/a7c2.names.result'])
            parsed=None
            try:parsed=nameworker.validate(raw,mode,build)
            except ValueError:
                if success:raise
            if (parsed is not None)!=success or not machine.readonly:
                raise ValueError('Exact names transaction status differed: '+name)
            wanted=targets if mode==1 and success else originals
            if any(bytes(machine.files['/usr/share/app/'+n])!=r for n,r in wanted.items()):
                raise ValueError('Exact names resource content differs: '+name)
            if not success and any('.a7c2-lut-' in p for p in machine.files):
                raise ValueError('Failed exact name transaction left a backup/stage')
            if mode==0 and (machine.renames or 40 in machine.calls):
                raise ValueError('Name preflight mutated the synthetic filesystem')
            if name=='names-install-all68':committed={p:bytes(r) for p,r in machine.files.items()}
            oracles.append(machine.oracle);rows.append({'case':name,'passed':True,'resources':68,'host_sha_oracle_calls':len(machine.oracle_calls)})
        finally:del machine;gc.collect()
    for name,mode,after_ap,remove_backups in (
        ('names-inverse-all68',2,original_ap,False),
        ('names-inverse-reconstruct-after-cleanup',2,original_ap,True),
        ('names-postacceptance-cleanup',3,target_ap,False)):
        files=dict(committed);files[AP]=after_ap;files['/tmp/jiritsu/libJit.so']=b'synthetic-worker'
        if remove_backups:files={p:r for p,r in files.items() if not p.endswith('.original')}
        files['/tmp/jiritsu/a7c2.names.request']=struct.pack('<8sII',b'A7NAM001',mode,0)
        machine=NamesOracleMachine(blob,files,metadata_blob=metadata)
        try:
            machine.run();nameworker.validate(bytes(machine.files['/tmp/jiritsu/a7c2.names.result']),mode,build)
            wanted=originals if mode==2 else targets
            if any(bytes(machine.files['/usr/share/app/'+n])!=r for n,r in wanted.items()) or not machine.readonly:
                raise ValueError('Exact names inverse/cleanup differed: '+name)
            if mode==3 and any(p.endswith('.original') for p in machine.files):
                raise ValueError('Postacceptance name cleanup left old links')
            oracles.append(machine.oracle);rows.append({'case':name,'passed':True,'resources':68,'host_sha_oracle_calls':len(machine.oracle_calls)})
        finally:del machine;gc.collect()
    result={'schema':'a7cr-slot1-name-transaction-simulation/1','passed':True,'worker_sha256':{'names_stage':package['workers']['names_stage']['sha256']},
        'actual_full_resource_cases':rows,'resource_count':68,'selected_mask':1,'hash_oracle_routines':oracles,'symbol_metadata_proof':metadata_proof,
        'camera_accessed':False,'hardware_or_power_failure_verified':False,
        'limits':['Actual 68-resource names worker and full source/target bytes; hash_path alone uses a host hashlib/stat oracle inside Unicorn.',
                  'Native resource transformation, hardlinks, staging, rename, inverse reconstruction and cleanup execute in the synthetic syscall model.',
                  'No camera filesystem timing, ownership implementation, native full-size hash loop or physical restoration is established.']}
    path=output/'names.private.json';prep._private_json(path,result)
    return path,result


def validate(package_path):
    package_path=Path(package_path).resolve();package=prep._read_json(package_path)
    if package.get('schema')!=prep.SCHEMA or package.get('ready_for_write') is not False:
        raise ValueError('Only a prepared nonready package may be evaluated')
    # Recheck checkpoint/material identity; this never acquires USB or fresh evidence.
    material=prep._load_material();baseline=prep._load_baseline()
    checkpoint=prep._read_checkpoint(ROOT/package['checkpoint'],material,baseline)
    if (prep.sha(checkpoint['raw'])!=package['checkpoint_sha256']
            or checkpoint['fields']!=package['settings'] or checkpoint['raw_evidence']!=package['checkpoint_raw_evidence']
            or package['body_binding']!=baseline.binding or package['names']!={'1':'Classic Chrome'} or package['selected_mask']!=1):
        raise ValueError('Prepared body/checkpoint/raw native evidence changed')
    for kind in ('AP','CP'):
        if any(package['programs'][kind][key]!=material['manifest']['programs'][kind][key]
               for key in ('source_sha256','candidate_sha256','bytes')):
            raise ValueError('Prepared package does not match the reviewed single-slot candidate')
    if set(package['resources'])!=set(checkpoint['resources']):
        raise ValueError('Prepared name resource scope changed')
    output=package_path.parent/'simulation'
    output.mkdir(exist_ok=False,mode=0o700)
    program_path,programs=check_programs(package,output)
    names_path,names=check_names(package,output)
    package['validation_receipts']={**package.get('validation_receipts',{}),
        'native_programs':{'file':prep._relative(program_path),'sha256':prep.sha(program_path.read_bytes())},
        'names':{'file':prep._relative(names_path),'sha256':prep.sha(names_path.read_bytes())}}
    package['workers']['names_stage']['simulation_passed']=True
    package['native_worker_simulation_passed']=True
    package['missing_validations']=[x for x in package['missing_validations'] if not x.startswith('Simulate exact program') and not x.startswith('Simulate exact 68-resource')]
    # Host orchestration validation and human write authorization remain separate.
    prep._private_json(package_path,package)
    return {'program_case_count':len(programs['actual_full_size_worker_cases']),
            'name_case_count':len(names['actual_full_resource_cases']),'native_worker_simulation_passed':True,
            'ready_for_write':False,'camera_accessed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--package',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(validate(args.package),indent=2))
