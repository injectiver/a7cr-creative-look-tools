"""Reuse exact 16-span worker; simulate actual CC-to-three-look transitions."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path

from single_slot_runtime import sha
from check_portrait_loaded import run
from check_native_workers import Machine

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
SOURCE_AP_HASH='585c9bf786600c24926f29432cf263c2e2ee76a8d00975e249c57641dfb56c71'


def build(output,candidate):
    output=Path(output).resolve();candidate=Path(candidate).resolve()
    if output.exists():raise ValueError('Preserve previous reader outputs')
    base=ROOT/'private/single-slot-runtime/candidate-reader/runtime.private.json'
    original=json.loads(base.read_text())
    source=ROOT/'private/single-slot-install/classic-chrome/payload/candidate-AP.private.bin'
    cm=json.loads((candidate/'candidate.private.json').read_text());target=candidate/'candidate-AP.private.bin'
    if (cm.get('schema')!='a7cr-portrait-slots-candidate/1' or cm.get('selected_mask')!=7
            or cm['programs']['AP']['source_sha256']!=SOURCE_AP_HASH
            or sha(source.read_bytes())!=SOURCE_AP_HASH
            or sha(target.read_bytes())!=cm['programs']['AP']['candidate_sha256']):
        raise ValueError('Incremental AP source/target identity differs')
    spec=original['worker'];blob=(ROOT/spec['file']).read_bytes()
    if (not original.get('simulation_passed') or len(original['spans'])!=16
            or sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes']):
        raise ValueError('Reviewed source reader bytes/spans changed')
    output.mkdir(parents=True,exist_ok=False)
    manifest=deepcopy(original)
    manifest.update(schema='a7cr-portrait-slots-code-reader/1',simulation_passed=False,
        source_manifest=str(base.relative_to(ROOT)),source_manifest_sha256=sha(base.read_bytes()),
        source_program_sha256=SOURCE_AP_HASH,candidate_program_sha256=cm['programs']['AP']['candidate_sha256'],
        worker_reused_exact=True,camera_executed=False)
    path=output/'runtime.private.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
    run(Machine,path,{'original':source,'candidate':target})
    report=output/'simulation.private.json';proof=json.loads(report.read_text())
    proof.update(worker_sha256=spec['sha256'],source_program_sha256=SOURCE_AP_HASH,
        candidate_program_sha256=cm['programs']['AP']['candidate_sha256'],
        actual_compiled_reader_executed=True,passed=all(c['passed'] for c in proof['results']))
    report.write_text(json.dumps(proof,indent=2)+'\n')
    manifest=json.loads(path.read_text());manifest.update(simulation_report=str(report.relative_to(ROOT)),
        simulation_report_sha256=sha(report.read_bytes()))
    path.write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();build(args.output,args.candidate)
