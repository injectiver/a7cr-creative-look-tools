"""Read post-reload disk/resources/settings and sixteen actual AP spans."""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import fcntl
import json
import os

from install_six_luts import Package,Session,Job,ROOT,durable_json,private_owner,sha
from diagnose_fl23 import invoke as runtime_invoke


def validate_post_state(package,current,runtime):
    if not runtime['ok'] or not runtime['all_loaded_ap_spans_match_candidate']:
        raise ValueError('Actual loaded AP spans differ from six-look target; do not reinstall')
    if runtime['boot_id']==package.checkpoint['loaded_ap']['boot_id']:
        raise ValueError('A new kernel boot has not been established; do not reinstall')
    for source,state in current.items():
        for f in package.fields:
            if state[0][f['key']].data!=bytes.fromhex(f['after']):
                raise ValueError(f'Selected {source} look/adjustment differs: {f["key"]:08x}')
        for key,value in package.fl23.bindings['candidate'].items():
            if state[0][key].data!=value:raise ValueError('A native FL23 binding changed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--physical-accepted',action='store_true',help='Owner confirmed six names, preview, new photos/playback and original FL/FL2/FL3; then remove only owned old resource hardlinks.')
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Use sudo in your terminal for Mac USB capture')
    os.umask(0o077);package=Package()
    state=json.loads((package.root/'state.private.json').read_text())
    if state['phase'] not in ('INSTALLED_PENDING_COLD_START','MACHINE_VERIFIED_PENDING_PHOTOS'):
        raise ValueError('This package is not awaiting post-installation verification')
    manifest=json.loads((package.root/'runtime/runtime.private.json').read_text())
    if not manifest['simulation_passed'] or len(manifest['spans'])!=16:
        raise ValueError('Six-look read-only runtime diagnostic is not validated')
    spec=manifest['worker'];blob=(ROOT/spec['file']).read_bytes()
    if sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes']:raise ValueError('Reviewed runtime worker changed')
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        attempt=package.root/('verify-'+stamp);attempt.mkdir(exist_ok=False);private_owner(attempt,True)
        job=Job(package,attempt)
        try:
            with Session(package,job.record) as camera:
                job.body(camera);job.program_state(camera,'post-reload','installed');job.titles(camera,True)
                current=job.snapshots(camera,'post-reload')
                runtime=runtime_invoke(camera,blob,manifest['spans'],package,attempt,job.record)
                validate_post_state(package,current,runtime)
                job.record('loaded_six_ap_verified',runtime=runtime,new_boot=True,running_cp_memory_directly_read=False)
                if args.physical_accepted:
                    job.record('owner_asserted_physical_acceptance',six_names_preview_photos_playback_and_original_looks=True)
                    job.names_native(camera,3)
            phase='COMPLETE' if args.physical_accepted else 'MACHINE_VERIFIED_PENDING_PHOTOS'
            durable_json(attempt/'verification.private.json',dict(phase=phase,loaded_ap=runtime,
                complete_programs_resources_and_selected_settings_verified=True,
                owner_physical_acceptance=args.physical_accepted,firmware_settings_or_wbi_written=False,
                owned_old_resource_links_cleaned=args.physical_accepted,running_cp_memory_directly_read=False))
            job.phase(phase,firmware_settings_or_wbi_written=False)
            print(json.dumps(dict(phase=phase,loaded_ap_spans=16,new_boot_confirmed=True,
                firmware_settings_or_wbi_written=False,attempt=str(attempt)),indent=2),flush=True)
        except BaseException as error:
            job.record('readonly_verification_stopped_no_retry',error_type=type(error).__name__,error=str(error))
            print('核验已停止；保留输出，不要重复刷写。',flush=True)
            raise
        finally:
            for store in package.stores:
                root=store.root.parent
                for path in [root,*root.rglob('*')]:private_owner(path,path.is_dir())


if __name__=='__main__':main()
