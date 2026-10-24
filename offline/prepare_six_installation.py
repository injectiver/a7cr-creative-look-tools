"""Bind the validated six-look candidate to a fresh dual-store checkpoint."""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

from build_lut_candidate import ROOT,OUT as CANDIDATE,sha
from build_native_workers import compile_worker,manifest_header,source
from inspect_sources import save_json

sys.path.insert(0,str(ROOT/'research/repos/a7c2-fl23-research/src/looks'))
from looktool.backupstore import Store
from looktool import nameworker

JOB=ROOT/'private/lut-install/six'
CHECKPOINT=ROOT/'private/lut-checkpoints/baseline'


def prepare():
    if JOB.exists():raise ValueError('Keep existing job immutable; do not rebuild over it')
    audit=json.loads((CANDIDATE/'audit.private.json').read_text())
    if not (audit['inverse_full_files_exact'] and audit['native_tests_passed'] and audit['ownership_audit_passed']):
        raise ValueError('Offline A7CR program checks are incomplete')
    cp=json.loads((CHECKPOINT/'checkpoint.private.json').read_text())
    if not cp['complete'] or not cp['normal_usb_return_confirmed'] or len(cp['settings'])!=54 or cp['resource_count']!=68:
        raise ValueError('Fresh checkpoint is incomplete')
    stores=[Store(ROOT/p,cp['body_key']) for p in cp['stores']]
    files={}
    for name,spec in cp['files'].items():
        copies=[s.read(spec) for s in stores]
        if copies[0]!=copies[1]:raise ValueError('Independent backup reconstruction differs')
        files[name]=copies[0]
    original={k:files[k] for k in ('AP','CP')}
    candidate={k:(CANDIDATE/f'candidate-{k}.private.bin').read_bytes() for k in original}
    windows=[]
    normalized={}
    for chip,kind in enumerate(original):
        spec=audit['programs'][kind]
        if sha(original[kind])!=spec['source_sha256'] or sha(candidate[kind])!=spec['candidate_sha256']:
            raise ValueError('Fresh programs do not match the validated port')
        inverse=bytearray(candidate[kind]);forward=bytearray(original[kind]);normalized[kind]=[]
        for w in sorted(spec['windows'],key=lambda x:x['offset']):
            old,new=bytes.fromhex(w['before_hex']),bytes.fromhex(w['after_hex'])
            for index in range(0,w['bytes'],4096):
                row=dict(offset=w['offset']+index,bytes=len(old[index:index+4096]),before_hex=old[index:index+4096].hex(),
                         after_hex=new[index:index+4096].hex(),chip=chip,purpose=w['purpose'])
                normalized[kind].append(row);windows.append(row)
            if original[kind][w['offset']:w['offset']+w['bytes']]!=old or candidate[kind][w['offset']:w['offset']+w['bytes']]!=new:
                raise ValueError('Checkpoint program window differs')
            forward[w['offset']:w['offset']+w['bytes']]=new;inverse[w['offset']:w['offset']+w['bytes']]=old
        if bytes(inverse)!=original[kind] or bytes(forward)!=candidate[kind]:raise ValueError('Checkpoint exact inverse differs')
    JOB.mkdir(parents=True,exist_ok=False)
    workers={}
    initial=[sha(original[k]) for k in original];final=[sha(candidate[k]) for k in original];sizes=[len(original[k]) for k in original]
    intermediate=[initial[0],final[1]]
    for name,before,after,rows,readonly in [
        ('program_check',initial,final,windows,True),
        ('cp_stage',initial,intermediate,normalized['CP'],False),
        ('ap_stage',intermediate,final,normalized['AP'],False)]:
        workers[name]=compile_worker(JOB/name,name,source('program',readonly),manifest_header(before,after,sizes,rows))
    # The already tested and physically used mode-0-only / one-shot WBI
    # workers have no firmware identities; preserve their exact reviewed bytes.
    prior=json.loads((ROOT/'private/native-workers/workers.private.json').read_text())
    for name in ('wbi_check','wbi_stage'):
        workers[name]=prior['workers'][name]
        blob=(ROOT/workers[name]['file']).read_bytes()
        if sha(blob)!=workers[name]['sha256']:raise ValueError('Reviewed WBI worker changed')
    names={i:x for i,x in enumerate(['Classic Neg.','Classic Chrome','Nostalgic Neg.','Eterna','GR Positive Film','GR Negative Film'],1)}
    resource_sources={name:files['resource/'+name] for name in nameworker.filenames()}
    os.environ['A7C2_ZIG_CACHE']=str(ROOT/'private/native-workers/lut-zig-cache')
    resource_target,names_build=nameworker.prepare(resource_sources,names,original['AP'],uuid.uuid4().hex[:16],
        JOB/'names',target_ap=candidate['AP'],label_ids=list(range(0x0200ab2c,0x0200ab32)))
    for item in names_build['files']:
        captured=next(r for r in cp['names'] if r['file']==item['file'])
        if item['before_sha256']!=captured['before_sha256'] or item['after_sha256']!=captured['after_sha256']:
            raise ValueError('Fresh resource plan changed')
    names_blob=Path(names_build['path']).read_bytes()
    workers['names_stage']=dict(file=str(Path(names_build['path']).relative_to(ROOT)),bytes=len(names_blob),sha256=sha(names_blob))
    result=dict(schema='a7cr-six-installation/1',model='ILCE-7CR',version='2.01',body_binding=cp['body_binding'],
        checkpoint=str(CHECKPOINT.relative_to(ROOT)),checkpoint_sha256=sha((CHECKPOINT/'checkpoint.private.json').read_bytes()),
        body_key=cp['body_key'],stores=cp['stores'],files=cp['files'],settings=cp['settings'],names=names,
        programs={k:dict(audit['programs'][k],windows=normalized[k]) for k in original},
        workers=workers,names_build=names_build,
        offline_program_tests=json.loads((CANDIDATE/'native-tests.private.json').read_text()),
        placement_audit_sha256=sha((CANDIDATE/'placement.private.json').read_bytes()),
        native_worker_simulation_passed=False,host_flow_tests_passed=False,device_preflight_passed=False,
        installed=False,camera_physical_tested=False)
    save_json(JOB/'package.private.json',result)
    save_json(JOB/'state.private.json',dict(phase='PREPARED_NOT_INSTALLED'))
    print(json.dumps(dict(job=str(JOB),program_windows={k:len(v) for k,v in normalized.items()},
        workers={k:v['bytes'] for k,v in workers.items()},native_worker_simulation_passed=False),indent=2))


if __name__=='__main__':prepare()
