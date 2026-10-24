"""Finalize reviewed local artifacts and tests; never open a camera/USB session."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path[:0]=[str(ROOT/'device'),str(ROOT/'offline'),str(ROOT)]
from single_slot_install import Package, PreparationBlocked, require_ready, validate_receipts
from fl23_install import durable_json


def sha(raw):return hashlib.sha256(raw).hexdigest()


def source_hashes():
    from tools.project_paths import source_root
    code=source_root()
    paths=[*sorted((code/'device').glob('*.py')),*sorted((code/'offline').glob('*.py')),
           *sorted((code/'device/native').glob('*.[ch]')),*sorted((code/'tools').glob('*.py')),
           code/'a7cr.py',code/'upstream.lock.json']
    return {str(path.relative_to(code)):sha(path.read_bytes()) for path in paths}


def finalize(workspace):
    workspace=Path(workspace).resolve()
    package=Package(workspace)
    state=json.loads((workspace/'state.private.json').read_text())
    m=deepcopy(package.manifest)
    if (state.get('phase')!='PREPARED_OFFLINE_PENDING_REVIEW' or m.get('ready_for_write') is not False
            or m.get('native_worker_simulation_passed') is not True
            or m.get('installation_authorized') is not False
            or any(p.name.startswith(('install-','restore-')) for p in workspace.iterdir())):
        raise PreparationBlocked('Only untouched, native-validated offline preparation can be finalized')
    before=source_hashes()
    folder=workspace/'host-validation';folder.mkdir(mode=0o700,exist_ok=False)
    env=dict(os.environ);env['PYTHONPATH']=os.pathsep.join((str(ROOT/'device'),str(ROOT/'offline'),str(ROOT)))
    with (folder/'public-host-tests.log').open('x') as output:
        subprocess.run([sys.executable,str(ROOT/'tools/run_tests.py')],cwd=ROOT,env=env,
                       stdout=output,stderr=subprocess.STDOUT,check=True)
    public=json.loads((ROOT/'private/validation/public-host-tests.private.json').read_text())
    # Run the offline candidate/checkpoint preparation tests separately; the
    # public runner intentionally discovers only device/ and tests/.
    offline_script='''import json,sys,unittest
suite=unittest.defaultTestLoader.loadTestsFromNames(['test_single_slot_candidate','test_prepare_single_slot_installation'])
r=unittest.TextTestRunner(verbosity=2).run(suite)
open(sys.argv[1],'x').write(json.dumps(dict(run=r.testsRun,skipped=len(r.skipped),failures=len(r.failures),errors=len(r.errors),successful=r.wasSuccessful()))+'\\n')
sys.exit(0 if r.wasSuccessful() else 1)
'''
    with (folder/'offline-tests.log').open('x') as output:
        subprocess.run([sys.executable,'-c',offline_script,str(folder/'offline-tests.private.json')],cwd=ROOT,env=env,
                       stdout=output,stderr=subprocess.STDOUT,check=True)
    offline=json.loads((folder/'offline-tests.private.json').read_text())
    if any(not r['successful'] or r['failures'] or r['errors'] for r in (public,offline)):
        raise PreparationBlocked('Host tests did not pass')
    if source_hashes()!=before:raise PreparationBlocked('Sources changed during validation')
    report={'schema':'a7cr-slot1-host-flow-validation/1','passed':True,
            'utc':datetime.now(timezone.utc).isoformat(),'camera_accessed':False,
            'tests_run':public['run']+offline['run'],'skipped':public['skipped']+offline['skipped'],
            'public_host_tests':public,'offline_tests':offline,'sources_sha256':before,
            'preflight':'Complete local Package revalidation; live body checks occur only on explicit install',
            'limits':'Mock host tests and native emulation do not prove physical boot, image quality or physical recovery'}
    receipt=folder/'host-flow.private.json';durable_json(receipt,report)
    m.setdefault('validation_receipts',{})['host_flow']={
        'file':str(receipt.relative_to(ROOT)),'sha256':sha(receipt.read_bytes())}
    m.update(ready_for_write=True,host_flow_tests_passed=True,installation_prepared=True,missing_validations=[])
    require_ready(m);validate_receipts(m,workspace)
    # No device preflight, installation authorization or physical flags are set.
    for key in ('camera_accessed','installation_authorized','device_preflight_passed','physical_ready'):
        if m.get(key) is not False:raise PreparationBlocked('Offline finalization cannot infer '+key)
    durable_json(workspace/'package.private.json',m)
    Package(workspace,require_write_ready=True)
    result={'phase':'PREPARED_NOT_INSTALLED','camera_accessed':False,'ready_for_write':True,
            'installation_authorized':False,'device_preflight_passed':False,'physical_ready':False,
            'tests_run':report['tests_run'],'tests_skipped':report['skipped']}
    durable_json(workspace/'state.private.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--finalize',action='store_true',help='Run local tests and finalize an untouched prepared package')
    args=p.parse_args()
    if args.finalize:result=finalize(args.workspace)
    else:
        package=Package(args.workspace,require_write_ready=True)
        result=json.loads((package.root/'state.private.json').read_text())
        result={**result,'local_artifacts_revalidated':True,'camera_accessed_by_this_check':False}
    print(json.dumps(result,ensure_ascii=False,indent=2))
