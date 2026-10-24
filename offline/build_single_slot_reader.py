"""Build/simulate sixteen source/candidate AP spans without camera access."""
from pathlib import Path
import re
import json
import sys
from elftools.elf.elffile import ELFFile

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path.insert(0,str(ROOT/'offline'))
from build_native_workers import compile_worker
from single_slot_runtime import PROC_HASH,sha


def build(output,candidate):
    output=Path(output).resolve();candidate=Path(candidate).resolve()
    if output.exists():raise ValueError('Keep original immutable reader outputs')
    cm=json.loads((candidate/'candidate.private.json').read_text())
    ap=candidate/'candidate-AP.private.bin'
    if cm['selected_mask']!=1 or sha(ap.read_bytes())!=cm['programs']['AP']['candidate_sha256']:
        raise ValueError('Unknown single-slot AP')
    proposed=[('converter',0x3528cd8,80),('title-helper',0x3528d28,52),
              ('title-entry',0x1b5ce5c,4),('native-map',0x4c7d4cc,12)]
    proposed += [(f'custom-title-{i+1}',0x59896f0+i*0xb8,4) for i in range(6)]
    proposed += [('FL23-capabilities',0x4b2f209,2),('FL2-menu',0x59892c8,2),('FL3-menu',0x5989380,2),
                 ('FL2-default-binding',0x4b4ab34,4),('FL3-default-binding',0x4b4ab3c,4),('FL23-fade-defaults',0x4b3ba94,12)]
    spans=[]
    with ap.open('rb') as f:
        elf=ELFFile(f)
        for name,offset,size in proposed:
            matches=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_offset']<=offset and offset+size<=s['p_offset']+s['p_filesz']]
            if len(matches)!=1 or size>128:raise ValueError('Source span is not backed by exactly one load segment')
            s=matches[0];spans.append(dict(name=name,offset=offset,bytes=size,virtual_offset=s['p_vaddr']+offset-s['p_offset']))
    old=ROOT/'private/runtime-diagnostic'
    probe=(old/'probe.c').read_bytes()
    if sha(probe)!=PROC_HASH:raise ValueError('Reviewed proc reader changed')
    output.mkdir(parents=True,exist_ok=False)
    (output/'probe.c').write_bytes(probe)
    text=(old/'runtime-read-only.c').read_text()
    entries=','.join('{%dUL,%dUL,%d}'%(s['offset'],s['virtual_offset'],s['bytes']) for s in spans)
    text,n=re.subn(r'static const struct Span spans\[\]=\{.*?\};','static const struct Span spans[]={'+entries+'};',text)
    if n!=1:raise ValueError('Original span declaration differs')
    for a,b in [('data[8][2][128]','data[16][2][128]'),('==2344','==4392'),('runtime.count=8','runtime.count=16'),('i<8;i++) {','i<16;i++) {')]:
        if text.count(a)!=1:raise ValueError('Reviewed read-only body differs')
        text=text.replace(a,b)
    spec=compile_worker(output,'slot1-code-reader',text)
    result=dict(schema='a7cr-slot1-code-reader/1',worker=spec,spans=spans,simulation_passed=False,
                persistent_camera_writes=False,camera_executed=False)
    manifest=output/'runtime.private.json'
    manifest.write_text(json.dumps(result,indent=2)+'\n')
    from check_native_workers import Machine
    from check_runtime_diagnostic import run
    run(Machine,manifest,{'original':ROOT/'private/install/fl23/payload/candidate-AP.private.bin','candidate':ap})
    return json.loads(manifest.read_text())


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True)
    m=p.parse_args();build(m.output,m.candidate)
