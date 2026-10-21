"""Finish the reviewed CP+names-complete job: AP, selected recipes, WBI only."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import struct

from install_six_luts import Package,Session,Job,ROOT,settings_plan,selected_preservation
from inspect_six_stop import review as review_failed_install
from fl23_install import durable_json,preserved
from preflight_fl23 import invoke_check,sha
from read_backup import backup_sections,CP_UNITS,private_owner
from diagnose_fl23 import invoke as runtime_invoke

INSPECTION='inspect-stop-20261020T141721802030Z'


def snapshots_from_events(package,events):
    result={}
    for source in ('memory','flash'):
        item=next(e for e in events if e['phase']=='incremental_readback_backed_up' and e['file']=='six-stop-inspection-'+source)
        copies=[s.read(item['spec']) for s in package.stores]
        if copies[0]!=copies[1]:raise ValueError('Inspection snapshot reconstructions disagree')
        result[source]=backup_sections(copies[0])
    return result


def historical_changes(package,old,current):
    """Record inter-session changes without overwriting or whitelisting them.

    All later mutations must preserve a new baseline captured in that session.
    Target recipes, their ST source, AP layout and CP calibration stay gated.
    """
    if settings_plan(package.programs['original']['AP'],current['memory'],current['flash'])!=package.fields:
        raise ValueError('Selected recipes or their ST source changed')
    selected={f['key'] for f in package.fields};result={}
    for source in current:
        before,after=old[source],current[source]
        for key in CP_UNITS:
            if before[1][key]!=after[1][key]:raise ValueError('Historical protected CP unit differs')
        scoped=lambda state:{k:v for k,v in state[0].items() if k>>16==0x02cf and k!=0x02cf0b6e}
        left,right=scoped(before),scoped(after)
        if left.keys()!=right.keys():raise ValueError('Historical writable settings layout differs')
        changes=[]
        for key,a in left.items():
            b=right[key]
            if a.attr!=b.attr or len(a.data)!=len(b.data):raise ValueError('Historical setting attributes or size differ')
            if a.data!=b.data:
                if key in selected:raise ValueError('A selected field changed since the failed install')
                changes.append(dict(key=f'{key:08x}',before_hex=a.data.hex(),current_hex=b.data.hex(),write_target=False))
        result[source]=changes
    return result


def review_inspection(package):
    failed,before=review_failed_install(package)
    folder=package.root/INSPECTION;raw=(folder/'events.private.json').read_bytes();events=json.loads(raw)
    last=events[-1]
    if (last['phase']!='inspection_stopped_no_retry' or last.get('error_type')!='TimeoutError'
        or last.get('error')!='Reads ended, but normal USB return was not confirmed; preserve this job'):
        raise ValueError('This is not the reviewed post-read USB-return timeout')
    if not any(e['phase']=='service_exit_returned' for e in events):raise ValueError('Service exit outcome is not recorded')
    native_phases={'native_invocation_intent','names_native_invocation_intent'}
    if any(e['phase'] in native_phases or e.get('operation','').startswith(('WRITE2_','WRITE41_','SAVE3_')) for e in events):
        raise ValueError('Inspection contained a persistent mutation attempt')
    reads={e['chip']:e for e in events if e['phase']=='complete_program_byte_readback' and e['tag']=='stop-inspection'}
    if set(reads)!=set(package.states['cp_only']) or any(reads[k]['sha256']!=sha(v) for k,v in package.states['cp_only'].items()):
        raise ValueError('Fresh complete programs are not the reviewed cp_only state')
    if not any(e['phase']=='complete_resource_readback' and e.get('named') is True and e.get('count')==68 for e in events):
        raise ValueError('Independent full readback of all 68 resources is incomplete')
    mirror=next(e for e in events if e['phase']=='readonly_resource_mirror_returned')
    target=package.named_resources['string_croatian_vertical.uxc']
    report=(folder/mirror['evidence']).read_bytes()
    if len(report)!=96:raise ValueError('Mirror evidence length differs')
    v=struct.unpack('<8sII4q2Q32s',report)
    if (v[:3]!=(b'A7CRM001',1,0) or any(v[i] for i in (3,4,6)) or v[7]!=len(target)
        or v[9]!=bytes.fromhex(sha(target)) or mirror['sha256']!=sha(target)):
        raise ValueError('Independent boundary-resource evidence differs')
    # Every read operation returned before the clean service-exit request.
    pending=0
    for event in events:
        if event['phase']=='read_intent':pending+=1
        elif event['phase']=='read_returned':pending-=1
        if pending not in (0,1):raise ValueError('Inspection command outcomes are ambiguous')
    if pending:raise ValueError('An inspection read was still outstanding')
    current=snapshots_from_events(package,events)
    changes=historical_changes(package,before,current)
    result=dict(schema='a7cr-six-reviewed-inspection/1',inspection=INSPECTION,events_sha256=sha(raw),
        failed_events_sha256=failed['events_sha256'],full_programs_match_cp_only=True,full_resources_verified=68,
        selected_source_and_cp_units_unchanged=True,historical_unselected_changes_preserved=changes,
        original_usb_return_timeout_preserved=True,normal_usb_must_be_confirmed_separately=True,
        requires_fresh_prewrite_baseline=True)
    return result,current


class CompletionJob(Job):
    def check_current_programs(self,camera,plan):
        spec=plan['program_check'];blob=(ROOT/spec['file']).read_bytes()
        if sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes']:raise ValueError('Completion check worker changed')
        return invoke_check(camera,'program_check',blob,self.attempt,self.record,plan['check_audit'])

    def complete(self,camera,plan):
        self.body(camera);self.program_state(camera,'completion-initial','cp_only')
        initial=self.snapshots(camera,'completion-initial')
        if settings_plan(self.package.programs['original']['AP'],initial['memory'],initial['flash'])!=self.package.fields:
            raise ValueError('Selected recipes/ST source changed since preparation')
        self.titles(camera,True)
        m=json.loads((ROOT/'private/runtime-diagnostic/runtime.private.json').read_text());spec=m['worker']
        blob=(ROOT/spec['file']).read_bytes()
        if not m['simulation_passed'] or sha(blob)!=spec['sha256']:raise ValueError('Loaded-AP diagnostic changed')
        live=runtime_invoke(camera,blob,m['spans'],self.package.fl23,self.attempt,self.record)
        if not live['ok'] or not live['all_loaded_ap_spans_match_candidate']:
            raise ValueError('Running source AP differs; preserve diagnosis')
        self.check_current_programs(camera,plan)
        self.native(camera,'wbi_check',0)
        before=self.snapshots(camera,'completion-before-write')
        for source in before:preserved(initial[source],before[source],{})
        self.phase('CP_AND_NAMES_REVERIFIED_NO_REPEAT_WRITES')
        self.phase('AP_PROGRAM_WRITE_INTENT');self.native(camera,'ap_stage',1)
        self.program_state(camera,'completion-after-ap','installed');self.phase('AP_PROGRAM_VERIFIED')
        self.phase('SELECTED_RECIPES_WRITE_INTENT');changed=False
        for field in self.package.fields:
            value=bytes.fromhex(field['after'])
            if before['memory'][0][field['key']].data!=value:
                camera.write_selected(field['key'],value);changed=True
        if changed:camera.save_selected()
        after=self.snapshots(camera,'completion-after-selected')
        for source in after:
            report=selected_preservation(before[source],after[source],self.package.fields)
            self.record('selected_saved_settings_and_preservation_verified',source=source,**report)
        self.phase('PROGRAMS_RESOURCES_SELECTED_SETTINGS_VERIFIED')
        self.native(camera,'wbi_stage',1);self.phase('WBI_INVALIDATED_VERIFIED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--battery-percent',type=int,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Use sudo in your terminal for Mac USB capture')
    if not 75<=args.battery_percent<=100:raise ValueError('Confirm current battery is at least 75 percent')
    os.umask(0o077);package=Package()
    plan=json.loads((package.root/'completion/completion.private.json').read_text())
    if not plan['native_simulation_passed'] or not plan['host_tests_passed'] or not plan['normal_usb_confirmed_after_timeout']:
        raise ValueError('Completion checks are not ready')
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        reviewed,current=review_inspection(package)
        if reviewed!=plan['inspection_review']:raise ValueError('Reviewed inspection evidence changed')
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        attempt=package.root/('complete-ap-'+stamp);attempt.mkdir(exist_ok=False);private_owner(attempt,True)
        job=CompletionJob(package,attempt)
        try:
            job.phase('AP_ONLY_COMPLETION_ATTEMPT_OPENED',battery_percent=args.battery_percent)
            with Session(package,job.record) as camera:job.complete(camera,plan)
            job.phase('INSTALLED_PENDING_COLD_START',cp_and_resource_writes_repeated=False)
            print(json.dumps(dict(phase='INSTALLED_PENDING_COLD_START',attempt=str(attempt),cp_and_resource_writes_repeated=False),indent=2),flush=True)
            print('全部写入和读回已结束。可拔 USB、正常关机；等存取灯熄灭后取出电池至少60秒，再装回开机。',flush=True)
        except BaseException as error:
            job.phase('STOPPED_INSPECTION_REQUIRED',error_type=type(error).__name__,error=str(error))
            print('已停止，未自动重试；保留输出和连接，不重复安装、关机或取电池。',flush=True);raise
        finally:
            for store in package.stores:
                root=store.root.parent
                for path in [root,*root.rglob('*')]:private_owner(path,path.is_dir())


if __name__=='__main__':main()
