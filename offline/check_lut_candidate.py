"""Exercise actual A7CR candidate instructions with synthetic CPU state.

Includes the upstream native controller/builder/uploader harness retargeted
to independently matched A7CR functions. No USB or real MMIO is accessed.
"""
from __future__ import annotations

import json
import random
import struct
import sys

from unicorn import Uc,UC_ARCH_ARM64,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm64_const import *
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R4,UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_PC
from build_lut_candidate import ROOT,OUT,INPUT,ENTRY,END,TITLE,GETTER,MAP,ap_code,sha
from inspect_sources import save_json


def ap_tests(source,target):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for at,size in [(0x3528000,0x2000),(0x1b5c000,0x2000),(MAP&~4095,4096),(0x30000000,0x3000)]:
        u.mem_map(at,size)
    u.mem_write(GETTER-4,source[GETTER-4:GETTER+36])
    u.mem_write(MAP,target[MAP:MAP+12])
    halt,stack=0x30002000,0x30001000
    count=0
    native=list(target[MAP:MAP+12])
    for mask in range(64):
        code,branch=ap_code(mask);u.mem_write(ENTRY,code);u.mem_write(GETTER,branch)
        u.ctl_remove_cache(ENTRY,END)
        for selector in range(18):
            for base in list(range(12))+[255]:
                for reg,value in [(UC_ARM64_REG_W0,selector),(UC_ARM64_REG_W1,base),(UC_ARM64_REG_X2,0x30000000),
                                  (UC_ARM64_REG_X30,halt),(UC_ARM64_REG_SP,stack)]:
                    u.reg_write(reg,value)
                u.mem_write(0x30000000,b'\xa5')
                u.emu_start(ENTRY,END if base>11 and selector!=16 else halt,count=50)
                pc=u.reg_read(UC_ARM64_REG_PC)
                if selector==16:expected=255
                elif base==0 and 10<=selector<=15 and mask&(1<<(selector-10)):expected=selector+239
                elif base<=11:expected=native[base]
                else:expected=165
                if u.mem_read(0x30000000,1)[0]!=expected or pc!=(END if expected==165 else halt) or u.reg_read(UC_ARM64_REG_SP)!=stack:
                    raise ValueError(f"A7CR converter differs: mask={mask} selector={selector} base={base}")
                count+=1
        for identity in [0,0x7f7,*range(0x7f8,0x7fe),0x7fe,0xffffffff]:
            for reg,value in [(UC_ARM64_REG_X0,0x112233445566),(UC_ARM64_REG_W1,identity),(UC_ARM64_REG_SP,stack),
                              (UC_ARM64_REG_X29,0x12345678),(UC_ARM64_REG_X30,halt)]:u.reg_write(reg,value)
            selected=0x7f8<=identity<=0x7fd and bool(mask&(1<<(identity-0x7f8)))
            u.emu_start(GETTER-4,halt if selected else GETTER+4,count=40)
            if selected:
                if (u.reg_read(UC_ARM64_REG_W0)!=0x0200ab2c+identity-0x7f8 or u.reg_read(UC_ARM64_REG_SP)!=stack
                        or u.reg_read(UC_ARM64_REG_X29)!=0x12345678 or u.reg_read(UC_ARM64_REG_PC)!=halt):
                    raise ValueError("Selected A7CR title ABI differs")
            elif (u.reg_read(UC_ARM64_REG_X0)!=0x112233445566 or u.reg_read(UC_ARM64_REG_W1)!=identity
                    or u.reg_read(UC_ARM64_REG_SP)!=stack-16 or u.reg_read(UC_ARM64_REG_X29)!=stack-16
                    or bytes(u.mem_read(stack-16,16))!=struct.pack('<QQ',0x12345678,halt)):
                raise ValueError("Native title continuation/frame differs")
            count+=1
    return count


def harness():
    path=ROOT/"research/repos/a7c2-fl23-research/src/looks/tests/test_preview_native.py"
    text=path.read_text()
    # Its public harness is reviewed in full. Exclude private-fixture loader
    # and all historical exact-SHA test classes, not admission guards.
    start=text.index('from unicorn import')
    text='import json,os,random,struct,unittest\nfrom pathlib import Path\n'+text[start:text.index('class NativePreviewTests')]
    replacements={'0xec7c20':'0xec6a2c','0x42cf44':'0x42d15c','0x23dc2c':'0x23dc4c',
        '0x78aa20':'0x78ac38','0x61e60c':'0x61e824','0x607264':'0x60747c',
        '0x6073c4':'0x6075dc','0xb4457a':'0xb443d8','0x23d380':'0x23d3a0','0x42cd28':'0x42cf40'}
    for a,b in replacements.items():text=text.replace(a,b)
    env={};exec(compile(text,str(path),"exec"),env)
    return env


def cp_tests(before,after):
    env=harness();schedule=env['schedule']
    count=0
    no_retry=bytearray(after);no_retry[0x13555a:0x13555e]=before[0x13555a:0x13555e]
    no_retry=bytes(no_retry)
    for marker in range(249,255):
        for consumer in range(4):
            for root3 in (0,1):
                rows=[(marker,consumer,False),(marker,consumer,True),(marker,consumer,True)]
                old,_=schedule(no_retry,rows,root3=root3)
                new,counters=schedule(after,rows,root3=root3)
                if old[1]['hardware_bytes_match'] or old[2]['hardware_bytes_match']:
                    raise ValueError("Dropped-submit baseline did not reproduce on A7CR")
                if not new[1]['hardware_bytes_match'] or not new[2]['hardware_bytes_match'] or counters['builds']!=1:
                    raise ValueError("A7CR native v4 preview upload differs")
                count+=1
    for seed in range(4):
        rng=random.Random(seed);rows=[]
        for _ in range(40):
            m,c=rng.randrange(249,255),rng.randrange(4)
            rows.extend([(m,c,False),(m,c,True)])
        states,_=schedule(after,rows)
        if not all(s['hardware_bytes_match'] for s in states if s['submitted']):
            raise ValueError("Random A7CR preview schedule differs")
        count+=1
    native=[(m,0,True) for m in [0,1,2,3,5,13,15,16,17,18,19,20,255]]
    for flag in (0,1):
        for direct in (0,1):
            for domain in (0,8,11):
                for root3 in (0,1):
                    kwargs=dict(flag=flag,direct=direct,domain=domain,root3=root3)
                    a=schedule(before,native,**kwargs);b=schedule(after,native,**kwargs)
                    if a!=b:raise ValueError("An original A7CR/FL23 controller path changed")
                    count+=1
    for negative in [{'invalid':True},{'effect_off':True},{'bank':False}]:
        states,_=schedule(after,[(m,0,True) for m in range(249,255)],**negative)
        if any(s['enabled'] for s in states):raise ValueError("Invalid/disabled A7CR LUT became active")
        count+=1
    # Snapshot/direct controller variants retain the native uploader gate.
    # Domain zero with flag=1 selects native domain 3, which has no preview
    # upload request. An enabled effect alone is not a submitted MMIO bank.
    for flag,direct in ((1,0),(0,1),(1,1)):
        for domain in (0,8,11):
            for root3 in (0,1):
                states,_=schedule(after,[(m,0,True) for m in range(249,255)],flag=flag,direct=direct,root3=root3,domain=domain)
                if any((s['uploaded'] or s['dirty']) and not s['hardware_bytes_match'] for s in states):
                    raise ValueError(f"A7CR snapshot/direct requested packed table differs: {flag=} {direct=} {root3=} {domain=}")
                if flag==1 and domain==0 and direct==0 and any(s['uploaded'] or s['dirty'] for s in states):
                    raise ValueError("Native domain-3 uploader gate changed")
                count+=1
    # Header corruption in each checksum must disable exactly that custom
    # table, while still accepting the other five.
    for slot in range(6):
        bad=bytearray(after);bad[0x8008+slot*4]^=1
        states,_=schedule(bytes(bad),[(m,0,True) for m in range(249,255)])
        if states[slot]['enabled'] or any(not s['hardware_bytes_match'] for i,s in enumerate(states) if i!=slot):
            raise ValueError("A7CR per-table integrity gate differs")
        count+=1
    return count


def gamma_tests(before,after):
    machines=[]
    for image in (before,after):
        u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.mem_map(0x108000,(len(image)+4095)&~4095)
        u.mem_write(0x108000,image);u.mem_map(0x30000000,0x2000);machines.append(u)
    for flag in (0,1):
        for mode in range(256):
            results=[]
            for index,u in enumerate(machines):
                for reg,value in [(UC_ARM_REG_R0,0 if index==0 and 249<=mode<=254 else mode),
                                  (UC_ARM_REG_R1,0xabcdef),(UC_ARM_REG_R4,flag),
                                  (UC_ARM_REG_SP,0x30001000),(UC_ARM_REG_LR,0x30000001)]:u.reg_write(reg,value)
                u.emu_start((0x240852 if index==0 else 0xc2f500)|1,0x30000000,count=60)
                results.append(tuple(u.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_SP,UC_ARM_REG_PC)))
            if results[0]!=results[1]:raise ValueError('Custom ST normalization changed a native/FL23 gamma route')
    return 512


def main():
    audit=json.loads((OUT/"audit.private.json").read_text())
    old={k:(INPUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    new={k:(OUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    if any(sha(new[k])!=audit['programs'][k]['candidate_sha256'] or sha(old[k])!=audit['programs'][k]['source_sha256'] for k in old):
        raise ValueError("Native test input changed")
    result=dict(schema='a7cr-six-native-tests/1',device_access=False,
        ap_instruction_cases=ap_tests(old['AP'],new['AP']),
        cp_native_controller_schedules=cp_tests(old['CP'],new['CP']),
        native_gamma_cases=gamma_tests(old['CP'],new['CP']),
        hardware_timing_emulated=False,physical_camera_tested=False)
    result['passed']=True
    save_json(OUT/'native-tests.private.json',result)
    audit['native_tests_passed']=True
    save_json(OUT/'audit.private.json',audit)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
