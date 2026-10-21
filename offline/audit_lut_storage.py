"""Audit mapped bounds, exact loaders and direct branch entry boundaries."""
from __future__ import annotations

import json
import struct
import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from build_lut_candidate import ROOT,OUT,INPUT,ENTRY,END,GETTER,MAP,HELPER,CHECKER,sha
from inspect_sources import save_json


def ap_incoming(raw):
    with (INPUT/'candidate-AP.private.bin').open('rb') as f:
        elf=ELFFile(f)
        sections=[s for s in elf.iter_sections() if s['sh_flags']&4]
        findings=[]
        for section in sections:
            start=section['sh_offset'];va=section['sh_addr']
            data=section.data();v=np.frombuffer(data[:len(data)//4*4],dtype='<u4').astype(np.uint64)
            at=np.arange(len(v),dtype=np.int64)*4+va
            def signed(x,bits):return np.where(x&(1<<(bits-1)),x-(1<<bits),x)
            modes=[((v&0x7c000000)==0x14000000,signed((v&0x3ffffff).astype(np.int64),26)*4),
                   ((v&0xff000010)==0x54000000,signed(((v>>5)&0x7ffff).astype(np.int64),19)*4),
                   ((v&0x7e000000)==0x34000000,signed(((v>>5)&0x7ffff).astype(np.int64),19)*4),
                   ((v&0x7e000000)==0x36000000,signed(((v>>5)&0x3fff).astype(np.int64),14)*4)]
            for mask,delta in modes:
                target=at+delta
                ix=np.flatnonzero(mask&(((target>=ENTRY)&(target<END))|((target>=GETTER)&(target<GETTER+4))))
                for i in ix:
                    source,dest=int(at[i]),int(target[i])
                    if not ENTRY<=source<END and dest!=ENTRY:
                        findings.append(dict(source=source,target=dest))
        if findings:raise ValueError('External AP branch enters replaced interior: '+str(findings))
    # The source FL23 converter has already retired the stock table. Check
    # original stock instructions which owned it, plus every ADD use of its
    # ADRP page in executable sections. An unrelated owner must stop the port.
    stock=(ROOT/'private/components/ILCE-7CR_2.01/appFw.so').read_bytes()
    uses=[]
    for section in sections:
        off,va=section['sh_offset'],section['sh_addr'];v=np.frombuffer(stock[off:off+section['sh_size']//4*4],dtype='<u4').astype(np.uint64)
        at=np.arange(len(v),dtype=np.int64)*4+va
        imm=((((v>>5)&0x7ffff)<<2)|((v>>29)&3)).astype(np.int64)
        imm=np.where(imm&(1<<20),imm-(1<<21),imm)
        target=(at&~4095)+imm*4096
        for i in np.flatnonzero(((v&0x9f000000)==0x90000000)&(target==(MAP&~4095))):
            rd=int(v[i]&31)
            for j in range(int(i)+1,min(int(i)+9,len(v))):
                ins=int(v[j]);add=((ins>>10)&4095)<<(12 if ins&(1<<22) else 0)
                if ins&0xff000000==0x91000000 and ((ins>>5)&31)==rd and int(target[i])+add==MAP:
                    uses.append(int(at[i]))
    if uses!=[ENTRY+28]:raise ValueError('Original native map has another or unknown owner: '+str(uses))
    return dict(external_interior_branches=[],original_map_owner=uses)


def cp_incoming(raw):
    # Decode every potential halfword entry near the three replaced controller
    # windows. Wider destinations are decoded from both possible boundaries;
    # this is stricter than linear disassembly through embedded switch data.
    h=np.frombuffer(raw[0x20000:0xb272e8],dtype='<u2').astype(np.uint64)
    at=np.arange(len(h),dtype=np.int64)*2+0x128000
    candidates=[]
    def sign(x,bits):return np.where(x&(1<<(bits-1)),x-(1<<bits),x)
    tests=[((h&0xf800)==0xe000,at+4+sign((h&0x7ff).astype(np.int64),11)*2),
           (((h&0xf000)==0xd000)&((h&0xf00)<0xe00),at+4+sign((h&255).astype(np.int64),8)*2),
           ((h&0xf500)==0xb100,at+4+(((h>>3)&31)|((h>>4)&32)).astype(np.int64)*2)]
    first,second=h[:-1],h[1:]
    s=(first>>10)&1;j1=(second>>13)&1;j2=(second>>11)&1
    i1=1^(j1^s);i2=1^(j2^s)
    imm=(s<<24)|(i1<<23)|(i2<<22)|((first&1023)<<12)|((second&2047)<<1)
    wide_target=at[:-1]+4+sign(imm.astype(np.int64),25)
    tests.append((((first&0xf800)==0xf000)&((second&0x9000)==0x9000),wide_target))
    windows=[(0x23d4d8,0x23d508),(0x23d55a,0x23d55e),(0x23d8e8,0x23d8ec)]
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for mask,target in tests:
        limit=len(mask);hit=np.zeros(limit,dtype=bool)
        for lo,hi in windows:hit|=(target[:limit]>=lo)&(target[:limit]<hi)
        for i in np.flatnonzero(mask&hit):
            source,dest=int(at[i]),int(target[i]);off=source-0x108000
            ins=next(decoder.disasm(raw[off:off+4],source),None)
            if ins is None or ins.mnemonic not in ('b','b.w','bl','cbz','cbnz','beq','bne','bhi','bls','bhs','blo','bgt','ble','bge','blt','bmi','bpl','bvc','bvs'):
                continue
            internal=any(lo<=source<hi for lo,hi in windows)
            if not internal and dest not in [lo for lo,hi in windows]:
                raise ValueError(f'CP branch may enter replaced interior: {source:x}->{dest:x}')
            candidates.append(dict(source=source,target=dest,mnemonic=ins.mnemonic,internal=internal))
    return candidates


def immediate_references(raw):
    h=np.frombuffer(raw[:len(raw)//2*2],dtype='<u2').astype(np.uint32)
    first,second=h[:-1],h[1:]
    lows=np.flatnonzero(((first&0xfbf0)==0xf240)&((second&0x8000)==0))
    highs=set(map(int,np.flatnonzero(((first&0xfbf0)==0xf2c0)&((second&0x8000)==0))))
    def value(i):return ((int(h[i])&15)<<12)|((int(h[i])&0x400)<<1)|((int(h[i+1])&0x7000)>>4)|(int(h[i+1])&255)
    observed=[]
    for i in lows:
        reg=(int(h[i+1])>>8)&15
        for j in range(int(i)+2,min(int(i)+22,len(h)-1)):
            if j in highs and ((int(h[j+1])>>8)&15)==reg:
                val=value(i)|(value(j)<<16)
                if any(lo<=val<hi for lo,hi in [(0x110000,0x111c9a),(HELPER,HELPER+256),(CHECKER,CHECKER+154)]):
                    observed.append((int(i)*2,j*2,val))
    reviewed={
        (0x2c22c6,0x2c22d2,0x110311):'Native event code passed to 0x9b7976 with log category 3; not dereferenced.',
        (0x9dc556,0x9dc55a,0x111111):'Hardware control bit pattern stored to register+0x14.',
        (0x9dc556,0x9dc57c,0x111111):'Over-approximation: register replaced by MOVS and MOVW before second MOVT.',
        (0x9dc578,0x9dc57c,0x111010):'Hardware control bit pattern stored to register+0x18.',
        (0x9dcd0c,0x9dcd10,0x111111):'Hardware control bit pattern stored to register+0x14.',
        (0xaa968c,0xaa96ae,0x11107c):'Over-approximation: LDR and MOVS replace r5 before MOVT; actual value is a control word.'}
    if set(observed)!=set(reviewed):raise ValueError('An unreviewed immediate reference reaches proposed LUT storage')
    return [dict(low_at=a,high_at=b,value=c,review=reviewed[a,b,c]) for a,b,c in observed]


def main():
    audit=json.loads((OUT/'audit.private.json').read_text())
    old={k:(INPUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    new={k:(OUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    if any(sha(old[k])!=audit['programs'][k]['source_sha256'] or sha(new[k])!=audit['programs'][k]['candidate_sha256'] for k in old):
        raise ValueError('Audit inputs changed')
    common=[]
    for name in ('loader_spi.bin','mini_ldr.bin','nor-loader_nor.bin'):
        left=(ROOT/f'private/components/ILCE-7CR_2.01/lut-references/{name}').read_bytes()
        right=(ROOT/f'private/components/ILCE-7CM2_2.01/lut-references/{name}').read_bytes()
        if left!=right:raise ValueError('A7CR loader variant differs; prefix preload proof does not carry')
        common.append(dict(file=name,bytes=len(left),sha256=sha(left)))
    cii=(ROOT/'private/components/ILCE-7CM2_2.01/cpapp-b.bin').read_bytes()
    if old['CP'][:0x1000]!=cii[:0x1000]:raise ValueError('CP bootstrap variant differs')
    original_header=struct.unpack_from('<12I',old['CP'],0x20124)
    changed_header=struct.unpack_from('<12I',new['CP'],0x20124)
    if changed_header[:1]+changed_header[2:]!=original_header[:1]+original_header[2:]:
        raise ValueError('A CP data/BSS descriptor moved')
    start,length=original_header[2],changed_header[1]
    for va,n in [(HELPER,256),(CHECKER,154)]:
        if not start<=va<va+n<=start+length<=original_header[5]:
            raise ValueError('New code exceeds loaded text / overlaps next section')
        if any(old['CP'][va-0x108000:va-0x108000+n]):raise ValueError('Executable tail source is occupied')
    boot=json.loads((ROOT/'private/offline/lut-port/bootstrap.private.json').read_text())
    if not boot['ok']:raise ValueError('A7CR bootstrap replay did not preserve tables')
    native=json.loads((OUT/'native-tests.private.json').read_text())
    if not native['passed']:raise ValueError('A7CR native paths have not passed')
    result=dict(schema='a7cr-lut-placement-audit/1',device_access=False,
        exact_common_loaders=common,cp_bootstrap_identical_to_pinned_reference=True,
        cp_bootstrap_replay=boot,ap=ap_incoming(old['AP']),cp_direct_entries=cp_incoming(old['CP']),
        cp_text_extension=dict(before=original_header[1],after=changed_header[1],next_section=original_header[5]),
        all_data_and_bss_descriptors_unchanged=True,cp_immediate_reference_review=immediate_references(old['CP']),
        prefix_preload=dict(nor_function_offset=0xf9c8,copy_offset=0xf9e8,copy_bytes=0x500000,
            follows_remainder_function=0xf8c8,storage_offset=0x8000,bytes=7322,
            evidence='Exact common NOR loader preloads first 5 MiB before remainder; CP bootstrap leaves the prefix reserved region intact.'),
        numeric_reference_review=dict(checker_tail_word_offset=0xb41e24,value=0x00c2ff92,
            signed16_pair=[-110,194],classification='Pair in signed 16-bit correction coefficient data; original executable text ends before this address, not a native callable entry.'),
        native_paths_verified=native,physical_boot_tested=False,passed=True)
    save_json(OUT/'placement.private.json',result)
    audit['ownership_audit_passed']=True
    save_json(OUT/'audit.private.json',audit)
    print(json.dumps(dict(common_loaders=len(common),bootstrap_instructions=boot['instructions'],
        ap_boundaries_passed=True,cp_boundaries_passed=True,data_bss_unchanged=True,passed=True),indent=2))


if __name__=='__main__':main()
