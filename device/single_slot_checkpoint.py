"""Fresh, body-bound slot-1 checkpoint. Read-only camera session only.

Captures two reconstructable copies of complete programs, Backup snapshots,
CP units and all native name resources. Runs reviewed temporary read-only AP
readers. No firmware/resource/setting/WBI writes or automatic retries.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import struct
import sys

from prepare_six_luts import CheckpointSession, RESOURCE_NAMES
from diagnose_fl23 import DiagnosticSession, NAMES as DIAG_NAMES, decode_probe, invoke as loaded_invoke
from fl23_install import Package, Job, PATHS, OWNED, store_private, durable_json, preserved
from read_backup import ROOT, private_owner, backup_sections, CP_UNITS
from preflight_fl23 import sha
sys.path.insert(0, str(ROOT/"offline"))
from single_slot_runtime import decode as decode_slot, AP_HASH

SLOT_EXTRA=frozenset(("a7cr.slot1-staged.so", "a7cr.slot1.bindings.result"))
SLOT_NAMES=DIAG_NAMES | SLOT_EXTRA
INSTALL=ROOT/"private/install/fl23"


class SlotSession(CheckpointSession):
    def select_temp(self, name):
        if name not in SLOT_NAMES:
            raise ValueError("Unknown slot checkpoint temporary path")
        status,_=self.temp_command(15,b"\0/tmp/jiritsu/"+name.encode("ascii")+b"\0")
        if status:
            self.healthy=False
            raise ValueError("Read-only slot path selection failed")


def slot_fields(ap, ram, saved):
    if sha(ap)!=AP_HASH:
        raise ValueError("Unknown A7CR program source")
    def descriptor(index):
        row=struct.unpack_from("<8I",ap,0x57c6710+index*32)
        if row[6]!=0x14ea+index or row[1]>>16!=0x02cf:
            raise ValueError("Native slot descriptor differs")
        return row
    base=descriptor(10)
    if base[:3]!=(3,0x02cf0cd0,0x10000):
        raise ValueError("Slot1 base descriptor differs")
    fields=[dict(slot=1,key=base[1],before_ram=ram[0][base[1]].data.hex(),
                 before_saved=saved[0][base[1]].data.hex(),after="00")]
    for i in range(8):
        target=descriptor(0x1520-0x14ea+i*18+10)
        st=descriptor(0x1520-0x14ea+i*18)
        if target[0]!=0 or target[2]!=0x40000:
            raise ValueError("Slot1 adjustment descriptor differs")
        value=ram[0][st[1]].data
        if len(value)!=4:
            raise ValueError("ST adjustment size differs")
        fields.append(dict(slot=1,key=target[1],before_ram=ram[0][target[1]].data.hex(),
                           before_saved=saved[0][target[1]].data.hex(),after=value.hex(),
                           source_st_key=st[1],source_st_saved=saved[0][st[1]].data.hex()))
    expected={0x02cf0cd0,*range(0x02cf0cf0,0x02cf0df0,0x20)}
    if {x['key'] for x in fields}!=expected:
        raise ValueError("Selected fields extend beyond slot1")
    return fields


def invoke_slot_probe(camera, manifest, attempt, record):
    if not manifest['read_only'] or not manifest['simulation_passed']:
        raise ValueError("Only a simulated, read-only slot probe may run here")
    spec=manifest['worker'];blob=(ROOT/spec['file']).read_bytes()
    if len(blob)!=spec['bytes'] or sha(blob)!=spec['sha256']:
        raise ValueError("Slot probe bytes changed")
    for name in sorted(SLOT_NAMES):
        if camera.read_temp(name,True) is not None:
            raise ValueError("Existing native temporary state; no overwrite or retry")
    camera.check_preload()
    expected={'a7cr.slot1-staged.so':blob,'libJit.so':blob}
    camera.write_temp('a7cr.slot1-staged.so',blob,expected)
    if camera.read_temp('a7cr.slot1-staged.so')!=blob:
        raise ValueError("Staged slot probe changed")
    record('slot1_readonly_probe_intent',sha256=sha(blob),persistent_writes=False)
    try:
        camera.write_temp('libJit.so',blob,expected)
        for name in ('a7cr.diag.probe.result','a7cr.slot1.bindings.result'):
            expected[name]=camera.read_temp(name)
            store_private(attempt/('slot1-'+name+'.private.bin'),expected[name])
        probe=decode_probe(expected['a7cr.diag.probe.result'])
        result=decode_slot(expected['a7cr.slot1.bindings.result'],read_only=True)
        if probe['status'] or probe['cleanup'] or probe['base']!=result['base'] or probe['pid']!=result['pid']:
            raise ValueError("Slot probe process identity differs")
    except BaseException:
        camera.healthy=False
        raise
    record('slot1_readonly_probe_returned',runtime=result)
    for name in ('libJit.so','a7cr.slot1.bindings.result','a7cr.diag.probe.result','a7cr.slot1-staged.so'):
        camera.remove_temp(name,expected)
    record('slot1_readonly_probe_cleanup_verified')
    return result


def review_readonly_stop(failed, package, probe):
    failed=Path(failed).resolve()
    if failed.parent!=(ROOT/'private/single-slot-checkpoints').resolve():
        raise ValueError('Read-only failure evidence escapes checkpoint root')
    partial=json.loads((failed/'checkpoint.partial.private.json').read_text())
    events_raw=(failed/'evidence/events.private.json').read_bytes();events=json.loads(events_raw)
    expected_error="File exists: '"+str(failed/'evidence/a7cr.diag.probe.result.private.bin')+"'"
    stopped=events[-1]
    if (partial.get('body_binding')!=package.binding or partial.get('complete') is not False
            or stopped.get('phase')!='stopped_no_retry' or stopped.get('error_type')!='FileExistsError'
            or expected_error not in stopped.get('error','')):
        raise ValueError('Only the precisely reviewed local log collision can be cleaned')
    intentions=[x for x in events if x['phase']=='slot1_readonly_probe_intent']
    loaded=[x for x in events if x['phase']=='runtime_readonly_invocation_returned']
    if (len(intentions)!=1 or intentions[0].get('sha256')!=probe['worker']['sha256']
            or len(loaded)!=1 or not loaded[0]['runtime']['all_loaded_ap_spans_match_candidate']
            or not any(x['phase']=='runtime_readonly_cleanup_verified' for x in events)
            or any(x['phase'] in ('native_invocation_intent','slot1_native_sync_intent','slot1_setting_write_intent') for x in events)):
        raise ValueError('Failure history includes unreviewed/mutating native work')
    return {'events_sha256':sha(events_raw),'loaded_runtime':loaded[0]['runtime'],'failed':str(failed)}


def cleanup_readonly_stop(camera, failed, package, manifest, attempt, record):
    evidence=review_readonly_stop(failed,package,manifest)
    camera.check_preload()
    if camera.read_temp('libJit.so',True) is not None:
        raise ValueError('An execution entry remains; preserve it for separate inspection')
    spec=manifest['worker'];blob=(ROOT/spec['file']).read_bytes()
    if sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes'] or not manifest['read_only']:
        raise ValueError('Reviewed read-only worker identity differs')
    known={'a7cr.slot1-staged.so':blob}
    for name in ('a7cr.slot1-staged.so','a7cr.diag.probe.result','a7cr.slot1.bindings.result'):
        actual=camera.read_temp(name,True)
        if actual is None:raise ValueError('Expected failed read-only temporary set is incomplete')
        store_private(attempt/('recovered-'+name+'.private.bin'),actual)
        if name in known and actual!=known[name]:raise ValueError('Temporary module differs from the read-only artifact')
        known[name]=actual
    proc=decode_probe(known['a7cr.diag.probe.result'])
    native=decode_slot(known['a7cr.slot1.bindings.result'],read_only=True)
    prior=evidence['loaded_runtime']
    if (proc['status'] or proc['cleanup'] or proc['pid']!=native['pid'] or proc['base']!=native['base']
            or native['pid']!=prior['pid'] or native['base']!=prior['base'] or native['boot_id']!=prior['boot_id']):
        raise ValueError('Temporary reports do not belong to the reviewed completed read-only execution')
    for name in sorted(SLOT_NAMES-set(known)-{'libJit.so'}):
        if camera.read_temp(name,True) is not None:raise ValueError('Preserve another unknown native temporary file')
    record('reviewed_readonly_temporary_cleanup_intent',failure=evidence,read_only_native_result=native,
           files={name:sha(value) for name,value in known.items()})
    for name in ('a7cr.slot1.bindings.result','a7cr.diag.probe.result','a7cr.slot1-staged.so'):
        camera.remove_temp(name,known)
    record('reviewed_readonly_temporary_cleanup_verified',no_firmware_settings_or_wbi_changes=True)
    return native


def capture(probe_path, destination, recover_owned_readonly_from=None):
    if os.geteuid()!=0:
        raise PermissionError("USB capture requires sudo in the owner's terminal")
    os.umask(0o077)
    probe=json.loads(probe_path.read_text())
    if not probe['read_only'] or not probe['simulation_passed'] or probe['selected_slot']!=1:
        raise ValueError("Read-only probe has not passed its required simulations")
    package=Package(INSTALL)
    if recover_owned_readonly_from is not None:
        review_readonly_stop(recover_owned_readonly_from,package,probe)
    baseline_state=json.loads((package.root/'state.private.json').read_text())
    if baseline_state.get('phase') not in ('FILES_SETTINGS_VERIFIED_PENDING_PHOTOS','COMPLETE'):
        raise ValueError("Current FL23 baseline has not completed post-restart verification")
    runtime=json.loads((ROOT/'private/runtime-diagnostic/runtime.private.json').read_text())
    if not runtime['simulation_passed']:
        raise ValueError("Loaded FL23 reader simulation is incomplete")
    destination=destination.resolve()
    if destination.exists() or destination.parent!=(ROOT/'private/single-slot-checkpoints').resolve():
        raise ValueError("Use a new direct child of private/single-slot-checkpoints")
    destination.mkdir(parents=True,exist_ok=False);private_owner(destination,True)
    copies=[destination/'copy-a',destination/'copy-b']
    for p in copies:p.mkdir();private_owner(p,True)
    attempt=destination/'evidence';attempt.mkdir();private_owner(attempt,True)
    job=Job(package,attempt);files={}
    def store(name,raw):
        for folder in copies:
            target=folder/name
            if target.parent!=folder:
                target.parent.mkdir(parents=True,exist_ok=True);private_owner(target.parent,True)
            store_private(target,raw)
        if any((folder/name).read_bytes()!=raw for folder in copies):
            raise ValueError("Independent checkpoint copies disagree")
        files[name]={'bytes':len(raw),'sha256':sha(raw)}
        durable_json(destination/'checkpoint.partial.private.json',dict(complete=False,files=files,
            model='ILCE-7CR',firmware='2.01',body_binding=package.binding))
    def snapshots(camera,tag):
        out={}
        for memory,name in ((True,'memory'),(False,'flash')):
            raw=camera.snapshot(memory);store(tag+'-'+name+'.bin',raw)
            sections=backup_sections(raw)
            serial=sections[0][0x00e70003].data
            if len(serial)!=4 or sha(serial.hex().encode('ascii'))!=package.binding['ap_serial_sha256']:
                raise ValueError("Checkpoint AP identity changed")
            for key in CP_UNITS:
                expected=package.units['candidate'].get(key,package.protected.get(key))
                if sections[1][key].data!=expected:
                    raise ValueError("Protected CP color/calibration unit changed")
                store(f'{tag}-{name}-cp-{key:08x}.bin',sections[1][key].data)
            out[name]=sections
        return out
    try:
        with (ROOT/'private/device.lock').open('a') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with SlotSession(package,job.record) as camera:
                job.body(camera)
                if recover_owned_readonly_from is not None:
                    cleanup_readonly_stop(camera,recover_owned_readonly_from,package,probe,attempt,job.record)
                ap=None
                for kind,path in PATHS.items():
                    raw=camera.read_program(path)
                    if raw!=package.programs['candidate'][kind]:
                        store('unexpected-'+kind+'.bin',raw)
                        raise ValueError("Current programs no longer match the reviewed FL23 baseline")
                    store(kind+'.bin',raw)
                    if kind=='AP':ap=raw
                initial=snapshots(camera,'before')
                fields=slot_fields(ap,initial['memory'],initial['flash'])
                print('只读备份 68 个菜单资源，保存两份独立副本。',flush=True)
                for i,name in enumerate(RESOURCE_NAMES):
                    store('resources/'+name,camera.read_resource(name))
                    if (i+1)%17==0:print(f'资源读取：{i+1}/68',flush=True)
                spec=runtime['worker'];blob=(ROOT/spec['file']).read_bytes()
                if sha(blob)!=spec['sha256'] or len(blob)!=spec['bytes']:
                    raise ValueError("Reviewed loaded-AP reader changed")
                loaded=loaded_invoke(camera,blob,runtime['spans'],package,attempt,job.record)
                if not loaded['ok'] or not loaded['all_loaded_ap_spans_match_candidate']:
                    raise ValueError("Actual loaded FL23 AP differs from disk")
                live=invoke_slot_probe(camera,probe,attempt,job.record)
                if live['boot_id']!=loaded['boot_id']:
                    raise ValueError("Boot identity changed during checkpoint")
                final=snapshots(camera,'after')
                preservation={kind:preserved(initial[kind],final[kind],{}) for kind in initial}
        result=dict(schema='a7cr-slot1-readonly-checkpoint/1',complete=True,model='ILCE-7CR',firmware='2.01',
                    utc=datetime.now(timezone.utc).isoformat(),body_binding=package.binding,
                    copies=['copy-a','copy-b'],files=files,fields=fields,resources=68,
                    native_ap_model=live,loaded_fl23=loaded,preservation=preservation,
                    normal_usb_return_confirmed=True,same_physical_volume=copies[0].stat().st_dev==copies[1].stat().st_dev,
                    firmware_resources_settings_or_wbi_written=False,
                    only_owned_temporary_readers_executed=True,installation_prepared=False)
        durable_json(destination/'checkpoint.private.json',result)
        job.record('SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE',normal_usb_return_confirmed=True)
        print(json.dumps({'phase':'SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE','checkpoint':str(destination),
            'copies':2,'resources':68,'native_slot1_base':live['before_bases'][10],
            'camera_persistent_writes':False},ensure_ascii=False,indent=2),flush=True)
    except BaseException as error:
        job.record('stopped_no_retry',error_type=type(error).__name__,error=str(error))
        print('只读检查已停止；保留日志，不要自动重复。',flush=True)
        raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--probe',type=Path,required=True)
    p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--recover-owned-readonly-from',type=Path)
    args=p.parse_args();capture(args.probe.resolve(),args.destination,args.recover_owned_readonly_from)
