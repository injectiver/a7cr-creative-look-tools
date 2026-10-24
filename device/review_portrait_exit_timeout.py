"""Inspect a fully completed install whose ordinary-USB wait alone timed out.

Never repeats installation. Local review redecodes original binary reports;
--verify subsequently performs a fresh, explicitly requested read-only session.
The original stop event remains in the installation history.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path

from portrait_slots_install import Package,Job,Session,selected_preservation
from portrait_slots_runtime import decode as decode_native
from fl23_install import decode_stage,decode_wbi_drop,durable_json,preserved
from diagnose_fl23 import decode_runtime,decode_probe
from read_backup import ROOT,backup_sections,private_owner
from preflight_fl23 import sha
from looktool import nameworker

ERROR='Reads ended, but normal USB return was not confirmed; preserve this job'


def require_complete_log(events,state,package):
    if (state.get('phase')!='STOPPED_INSPECTION_REQUIRED' or state.get('error_type')!='TimeoutError'
            or state.get('error')!=ERROR or not events or events[-1].get('phase')!='STOPPED_INSPECTION_REQUIRED'
            or events[-1].get('error_type')!='TimeoutError' or events[-1].get('error')!=ERROR):
        raise ValueError('Only an exactly identified post-write USB-return timeout is supported')
    starts=[e for e in events if e['phase']=='portrait_slots_command_started']
    if len(starts)!=1 or starts[0].get('command')!='install' or not 75<=starts[0].get('battery_percent',-1)<=100:
        raise ValueError('Not one power-confirmed installation')
    required=['DEVICE_PREFLIGHT_PASSED','PORTRAIT_SLOTS_SAVED_AND_NATIVE_ST_VERIFIED',
              'service_exit_intent','service_exit_returned','STOPPED_INSPECTION_REQUIRED']
    locations=[]
    for phase in required:
        at=[i for i,e in enumerate(events) if e['phase']==phase]
        if len(at)!=1:raise ValueError('Required completion phase absent or repeated: '+phase)
        locations.append(at[0])
    if locations!=sorted(locations):raise ValueError('Completion phase order differs')
    for first,last in (('read_intent','read_returned'),('native_invocation_intent','native_invocation_returned'),
                       ('portrait_native_invocation_intent','portrait_native_invocation_returned'),
                       ('portrait_slots_names_invocation_intent','portrait_slots_names_invocation_returned')):
        balance=0
        for event in events:
            if event['phase']==first:balance+=1
            elif event['phase']==last:balance-=1
            if balance not in (0,1):raise ValueError('Unpaired operation history')
        if balance:raise ValueError('An operation result remains unknown')
    for kind in ('cp_stage','ap_stage','wbi_stage'):
        completed=[(i,e) for i,e in enumerate(events) if e['phase']=='native_invocation_returned' and e.get('worker')==kind]
        clean=[i for i,e in enumerate(events) if e['phase']=='native_cleanup_verified' and e.get('worker')==kind]
        if (len(completed)!=1 or completed[0][1].get('mode')!=1 or completed[0][1]['report'].get('ok') is not True
                or len(clean)!=1 or not completed[0][0]<clean[0]<locations[2]):
            raise ValueError('Native completion/cleanup is missing: '+kind)
    for chip in ('AP','CP'):
        matches=[e for e in events if e['phase']=='complete_program_byte_readback'
                 and e.get('tag')=='after-ap' and e.get('chip')==chip]
        if (len(matches)!=1 or matches[0].get('sha256')!=sha(package.programs['candidate'][chip])
                or matches[0].get('bytes')!=len(package.programs['candidate'][chip])):
            raise ValueError('Final full program readback is missing: '+chip)
    names=[e for e in events if e['phase']=='portrait_slots_names_invocation_returned' and e.get('mode')==1]
    if len(names)!=1 or names[0]['report'].get('files')!=68 or not names[0]['report'].get('native_verified'):
        raise ValueError('Full name transaction is missing')
    if not any(e['phase']=='all_68_resource_bytes_verified' and e.get('state')=='named' for e in events):
        raise ValueError('All target resource byte readbacks are missing')
    predicates=[lambda e:e['phase']=='PORTRAIT_SLOTS_SAVED_AND_NATIVE_ST_VERIFIED',
                lambda e:e['phase']=='native_invocation_returned' and e.get('worker')=='cp_stage',
                lambda e:e['phase']=='portrait_slots_names_invocation_returned' and e.get('mode')==1,
                lambda e:e['phase']=='all_68_resource_bytes_verified' and e.get('state')=='named',
                lambda e:e['phase']=='native_invocation_returned' and e.get('worker')=='ap_stage',
                lambda e:e['phase']=='program_state_verified' and e.get('tag')=='after-ap' and e.get('state')=='installed',
                lambda e:e['phase']=='native_invocation_returned' and e.get('worker')=='wbi_stage',
                lambda e:e['phase']=='service_exit_intent']
    sequence=[]
    for predicate in predicates:
        found=[i for i,e in enumerate(events) if predicate(e)]
        if len(found)!=1:raise ValueError('Completion sequence is incomplete or repeated')
        sequence+=found
    if sequence!=sorted(sequence):raise ValueError('Persistent-stage completion order differs')


def review(workspace):
    package=Package(workspace,require_write_ready=True)
    state_path=package.root/'state.private.json';state_raw=state_path.read_bytes();state=json.loads(state_raw)
    name=state.get('attempt','');attempt=(package.root/name).resolve()
    if not name.startswith('install-') or attempt.parent!=package.root or (package.root/name).is_symlink():
        raise ValueError('Unknown stopped installation path')
    events_path=attempt/'events.private.json';raw=events_path.read_bytes();events=json.loads(raw)
    require_complete_log(events,state,package)
    evidence={}
    def read(relative):
        data=(attempt/relative).read_bytes();evidence[relative]={'bytes':len(data),'sha256':sha(data)};return data
    for kind in ('cp_stage','ap_stage'):
        decoded=decode_stage(read(kind+'-mode1.private.bin'),kind,1,package)
        expected=next(e['report'] for e in events if e['phase']=='native_invocation_returned' and e.get('worker')==kind)
        if not decoded['ok'] or decoded!=expected:raise ValueError('Original native binary report differs')
    wbi=decode_wbi_drop(read('wbi_stage-mode1.private.bin'))
    expected=next(e['report'] for e in events if e['phase']=='native_invocation_returned' and e.get('worker')=='wbi_stage')
    if not wbi['ok'] or wbi!=expected:raise ValueError('Original WBI report differs')
    report=nameworker.validate(read('names-1/result.private.bin'),1,package.manifest['names_build'])
    if report!=next(e['report'] for e in events if e['phase']=='portrait_slots_names_invocation_returned' and e.get('mode')==1):
        raise ValueError('Original name binary report differs')
    # Classifications are relative to the NEW package: the loaded-before code
    # must be its exact source, the already installed single-slot CC version.
    loaded=decode_runtime(read('loaded-before/a7cr.diag.runtime.result.private.bin'),package.readers['original']['spans'],package)
    proc=decode_probe(read('loaded-before/a7cr.diag.probe.result.private.bin'))
    if not loaded['ok'] or (loaded['pid'],loaded['base'])!=(proc['pid'],proc['base']) or proc['status'] or proc['cleanup']:
        raise ValueError('Original source process evidence is incomplete')
    for span,row in zip(package.readers['original']['spans'],loaded['spans']):
        expected=package.programs['original']['AP'][span['offset']:span['offset']+span['bytes']].hex()
        if row['loaded_hex']!=expected or row['disk_hex']!=expected:raise ValueError('Unknown original loaded code')
    native=None
    for slot in (2,3):
        intent=next(e for e in events if e['phase']=='portrait_native_invocation_intent' and e.get('slot')==slot)
        worker=package.sync_worker(slot,intent['before'],0,require_current_st=True)
        if worker['worker']['sha256']!=intent['worker_sha256']:raise ValueError('Native CAS worker differs')
        native=decode_native(read(f'install-st-slot{slot}-native/a7cr.portrait.bindings.result.private.bin'),
                             read_only=False,selected_slot=slot,expected_before=intent['before'],target=0,require_current_st=True)
        if native!=next(e['runtime'] for e in events if e['phase']=='portrait_native_invocation_returned'
                        and e['runtime'].get('selected_slot')==slot):raise ValueError('Original CAS report differs')
    final_native=decode_native(read('install-st-slot3-post-model/a7cr.portrait.bindings.result.private.bin'),read_only=True)
    if (final_native['before_bases'][10:13]!=[0,0,0] or final_native['before_bases']!=native['after_bases']
            or any(final_native[k]!=loaded[k] for k in ('pid','base','boot_id'))):
        raise ValueError('Final native bases/process are not established')
    for source in ('memory','flash'):
        initial=backup_sections(read('initial-'+source+'.private.bin'))
        staged=backup_sections(read('install-st-slot3-after-'+source+'.private.bin'))
        final=backup_sections(read('install-final-'+source+'.private.bin'))
        desired={f['key']:bytes.fromhex(f['after']) for f in package.fields}
        selected_preservation(initial,staged,desired,native_targets={2:0,3:0})
        preserved(staged,final,{})
    proof={'schema':'a7cr-completed-install-exit-timeout-review/1','passed':True,
           'utc':datetime.now(timezone.utc).isoformat(),'attempt':attempt.name,
           'original_events_sha256':sha(raw),'original_state_sha256':sha(state_raw),
           'evidence':evidence,'all_persistent_writes_completed_and_read_back':True,
           'service_exit_returned':True,'original_normal_usb_return_confirmed':False,
           'fresh_cold_start_readonly_verification_required':True,'camera_opened_by_local_review':False}
    return package,attempt,events,proof,loaded['boot_id']


def verify(workspace):
    if os.geteuid()!=0:raise PermissionError("Run read-only USB verification with sudo in your own terminal")
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        package,original,events,proof,before_boot=review(workspace)
        attempt=package.root/('review-verify-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        attempt.mkdir();private_owner(attempt,True);durable_json(attempt/'review.private.json',proof)
        job=Job(package,attempt)
        try:
            job.record('reviewed_exit_timeout_readonly_verification_started',original_attempt=original.name)
            with Session(package,job.record) as camera:
                result=job.verify(camera,before_boot_id=before_boot)
            durable_json(attempt/'result.private.json',result)
            # Append truthful LATER completion after a new bound read-only
            # session; never remove or rewrite the original timeout event.
            if sha((original/'events.private.json').read_bytes())!=proof['original_events_sha256']:
                raise ValueError('Original installation history changed during review')
            now=datetime.now(timezone.utc).isoformat()
            events.extend([{'phase':'exit_timeout_reviewed_after_cold_start','utc':now,'review_attempt':attempt.name,
                            'original_timeout_preserved':True,'all_program_resource_settings_verified_now':True},
                           {'phase':'portrait_slots_command_complete','utc':now,'command':'install',
                            'normal_usb_return_confirmed':True,'completion_confirmed_by_later_readonly_verification':True,
                            'review_attempt':attempt.name}])
            durable_json(original/'events.private.json',events)
            job.phase(result['phase'],**{k:v for k,v in result.items() if k!='phase'})
            job.record('portrait_slots_command_complete',command='verify',normal_usb_return_confirmed=True)
            return result
        except BaseException as error:
            job.record('review_readonly_stopped_no_retry',error_type=type(error).__name__,error=str(error));raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--verify',action='store_true',help='After owner cold start, new read-only camera session; never install')
    args=p.parse_args()
    if args.verify:result=verify(args.workspace)
    else:result=review(args.workspace)[3]
    print(json.dumps(result if args.verify else {k:v for k,v in result.items() if k!='evidence'},ensure_ascii=False,indent=2))
