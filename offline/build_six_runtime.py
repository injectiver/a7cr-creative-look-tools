"""Expand the tested read-only AP diagnostic to the sixteen six-look spans."""
from __future__ import annotations
import json
import re
from elftools.elf.elffile import ELFFile
from build_native_workers import ROOT,compile_worker
from build_lut_candidate import OUT as CANDIDATE,ENTRY,TITLE,GETTER,MAP
from inspect_sources import save_json

OUT=ROOT/'private/lut-install/six-20261020-01/runtime'


def build():
    OUT.mkdir(parents=True,exist_ok=True)
    proposed=[('converter',ENTRY,80),('title-helper',TITLE,52),('title-entry',GETTER,4),('native-map',MAP,12)]
    proposed += [(f'custom-title-{i+1}',0x59896f0+i*0xb8,4) for i in range(6)]
    proposed += [('FL23-capabilities',0x4b2f209,2),('FL2-menu',0x59892c8,2),('FL3-menu',0x5989380,2),
                 ('FL2-default-binding',0x4b4ab34,4),('FL3-default-binding',0x4b4ab3c,4),('FL23-fade-defaults',0x4b3ba94,12)]
    spans=[]
    with (CANDIDATE/'candidate-AP.private.bin').open('rb') as f:
        elf=ELFFile(f)
        for name,offset,size in proposed:
            matches=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_offset']<=offset and offset+size<=s['p_offset']+s['p_filesz']]
            if len(matches)!=1 or size>128:raise ValueError('Six-look AP span mapping differs')
            s=matches[0];spans.append(dict(name=name,offset=offset,bytes=size,virtual_offset=s['p_vaddr']+offset-s['p_offset']))
    old=ROOT/'private/runtime-diagnostic'
    (OUT/'probe.c').write_bytes((old/'probe.c').read_bytes())
    text=(old/'runtime-read-only.c').read_text()
    entries=','.join('{%dUL,%dUL,%d}'%(s['offset'],s['virtual_offset'],s['bytes']) for s in spans)
    text,n=re.subn(r'static const struct Span spans\[\]=\{.*?\};','static const struct Span spans[]={'+entries+'};',text)
    if n!=1:raise ValueError('Original diagnostic span declaration differs')
    for a,b in [('data[8][2][128]','data[16][2][128]'),('==2344','==4392'),('runtime.count=8','runtime.count=16'),('i<8;i++) {','i<16;i++) {')]:
        if text.count(a)!=1:raise ValueError('Original diagnostic body differs: '+a)
        text=text.replace(a,b)
    spec=compile_worker(OUT,'six-runtime-read-only',text)
    manifest=dict(schema='a7cr-six-runtime-readonly/1',worker=spec,spans=spans,simulation_passed=False,
        persistent_camera_writes=False,camera_executed=False)
    save_json(OUT/'runtime.private.json',manifest)
    print(json.dumps(dict(spans=len(spans),bytes=spec['bytes'],persistent_camera_writes=False)))


if __name__=='__main__':build()
