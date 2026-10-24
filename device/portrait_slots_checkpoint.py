"""Fresh read-only checkpoint of the installed Classic Chrome source.

Only existing, simulated read-only workers run. No program, name-resource,
recipe, calibration or retained-image writes, and no authentication retries.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import struct

from single_slot_install import Package, Job, Session
from single_slot_checkpoint import invoke_slot_probe
from fl23_install import PATHS, durable_json, preserved, store_private
from read_backup import ROOT, private_owner, backup_sections, CP_UNITS
from preflight_fl23 import sha
from prepare_six_luts import RESOURCE_NAMES
from looktool import devicesettings

SOURCE=ROOT/'private/single-slot-install/classic-chrome'
SOURCE_HASHES={'AP':'585c9bf786600c24926f29432cf263c2e2ee76a8d00975e249c57641dfb56c71',
               'CP':'8d006427e0279beaad957a5d811e9237b6105afbb8c7c88b6be715bc91e58a82'}
SLOTS=(2,3)


def require_same_process(loaded,native):
    if any(loaded[key]!=native[key] for key in ('pid','base','boot_id')):
        raise ValueError('Native AP process changed during read-only checkpoint')


def fields_from_descriptors(descriptor,ram,saved):
    """Only the two new slots; descriptor identity is checked by the caller."""
    fields=[]
    for slot in SLOTS:
        selector=slot+9;row=descriptor(selector)
        key=0x02cf0cd0+2*(slot-1)
        if row[:3]!=(3,key,0x10000) or any(len(s[0][key].data)!=1 for s in (ram,saved)):
            raise ValueError('Unknown selected base descriptor/value')
        if any(s[0][key].data[0]>11 for s in (ram,saved)):
            raise ValueError('Unknown selected base enum')
        fields.append(dict(slot=slot,key=key,before_ram=ram[0][key].data.hex(),
                           before_saved=saved[0][key].data.hex(),after='00'))
        for i in range(8):
            target=descriptor(0x1520-0x14ea+i*18+selector)
            st=descriptor(0x1520-0x14ea+i*18)
            expected_key=0x02cf0cf0+2*(slot-1)+i*0x20
            if target[:3]!=(0,expected_key,0x40000) or st[0]!=0 or st[2]!=0x40000:
                raise ValueError('Unknown selected adjustment descriptor')
            if any(len(s[0][k].data)!=4 for s in (ram,saved) for k in (target[1],st[1])):
                raise ValueError('Adjustment field length differs')
            fields.append(dict(slot=slot,key=target[1],before_ram=ram[0][target[1]].data.hex(),
                               before_saved=saved[0][target[1]].data.hex(),after=ram[0][st[1]].data.hex(),
                               source_st_key=st[1],source_st_saved=saved[0][st[1]].data.hex()))
    if len(fields)!=18 or len({f['key'] for f in fields})!=18:
        raise ValueError('Two-slot field scope differs')
    if any(f['before_ram']!=f['before_saved'] for f in fields):
        raise ValueError('Selected recipes contain unsaved edits; preserve this checkpoint')
    devicesettings.require_save_preserves_unsaved(ram,saved,{f['key'] for f in fields})
    return fields


def slot_fields(ap,ram,saved):
    if sha(ap)!=SOURCE_HASHES['AP']:raise ValueError('Unknown installed Classic Chrome AP')
    def descriptor(index):
        row=struct.unpack_from('<8I',ap,0x57c6710+index*32)
        if row[6]!=0x14ea+index or row[1]>>16!=0x02cf:
            raise ValueError('Native A7CR descriptor identity differs')
        return row
    return fields_from_descriptors(descriptor,ram,saved)


def source_evidence(package):
    state=json.loads((SOURCE/'state.private.json').read_text())
    if state.get('phase') not in ('MACHINE_VERIFIED_PENDING_PHOTOS','COMPLETE'):
        raise ValueError('Installed Classic Chrome source is not machine-verified')
    attempt=(SOURCE/state['attempt']).resolve()
    if attempt.parent!=SOURCE.resolve() or not attempt.name.startswith('verify-'):
        raise ValueError('Source verification path differs')
    result_path=attempt/'result.private.json';raw=result_path.read_bytes();result=json.loads(raw)
    events_path=attempt/'events.private.json';events_raw=events_path.read_bytes();events=json.loads(events_raw)
    if (not events or events[-1].get('phase')!='single_slot_command_complete'
            or events[-1].get('normal_usb_return_confirmed') is not True
            or result.get('loaded_ap',{}).get('all_loaded_ap_spans_match_candidate') is not True
            or result['loaded_ap']['boot_id']==result.get('before_boot_id')):
        raise ValueError('Complete source cold-start verification evidence is missing')
    for kind,expected in SOURCE_HASHES.items():
        if sha(package.programs['candidate'][kind])!=expected:
            raise ValueError('Source programs differ from installed Classic Chrome')
        if not any(e.get('phase')=='complete_program_byte_readback' and e.get('chip')==kind
                   and e.get('sha256')==expected for e in events):
            raise ValueError('Source complete program readback evidence is missing')
    return {'file':str(result_path.relative_to(ROOT)),'sha256':sha(raw),
            'events_file':str(events_path.relative_to(ROOT)),'events_sha256':sha(events_raw)}


def capture(destination):
    if os.geteuid()!=0:raise PermissionError("Mac USB requires sudo in the owner's terminal")
    os.umask(0o077)
    package=Package(SOURCE,require_write_ready=True)
    verified=source_evidence(package)
    destination=Path(destination).resolve()
    if destination.exists() or destination.parent!=(ROOT/'private/portrait-slots-checkpoints').resolve():
        raise ValueError('Use a new direct child of private/portrait-slots-checkpoints')
    destination.mkdir(parents=True,exist_ok=False);private_owner(destination,True)
    copies=[destination/'copy-a',destination/'copy-b']
    for folder in copies:folder.mkdir();private_owner(folder,True)
    attempt=destination/'evidence';attempt.mkdir();private_owner(attempt,True)
    job=Job(package,attempt);files={}
    def store(name,raw):
        for folder in copies:
            path=folder/name
            if path.parent!=folder:path.parent.mkdir(exist_ok=True);private_owner(path.parent,True)
            store_private(path,raw)
        if any((folder/name).read_bytes()!=raw for folder in copies):
            raise ValueError('Independent checkpoint copy readback differs')
        files[name]={'bytes':len(raw),'sha256':sha(raw)}
        durable_json(destination/'checkpoint.partial.private.json',{
            'complete':False,'files':files,'model':'ILCE-7CR','firmware':'2.01','body_binding':package.binding})
    def snapshots(camera,tag):
        captured={}
        for memory,name in ((True,'memory'),(False,'flash')):
            raw=camera.snapshot(memory);store(tag+'-'+name+'.bin',raw)
            sections=backup_sections(raw)
            serial=sections[0][0x00e70003].data
            if len(serial)!=4 or sha(serial.hex().encode('ascii'))!=package.binding['ap_serial_sha256']:
                raise ValueError('Checkpoint AP body identity differs')
            for key in CP_UNITS:
                expected=package.fl23.units['candidate'].get(key,package.fl23.protected.get(key))
                if sections[1][key].data!=expected:raise ValueError('Protected CP/calibration unit changed')
                store(f'{tag}-{name}-cp-{key:08x}.bin',sections[1][key].data)
            for key,value in package.fl23.bindings['candidate'].items():
                if sections[0][key].data!=value:raise ValueError('Preserved FL2/FL3 binding changed')
            captured[name]=sections
        return captured
    try:
        with (ROOT/'private/device.lock').open('a') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with Session(package,job.record) as camera:
                job.body(camera)
                for kind,path in PATHS.items():
                    raw=camera.read_program(path)
                    if raw!=package.programs['candidate'][kind]:
                        store('unexpected-'+kind+'.bin',raw)
                        raise ValueError('Current programs differ from the installed Classic Chrome source')
                    store(kind+'.bin',raw)
                initial=snapshots(camera,'before')
                fields=slot_fields(package.programs['candidate']['AP'],initial['memory'],initial['flash'])
                print('只读备份当前 Classic Chrome 版本与 68 份菜单资源，保存两份副本。',flush=True)
                for index,name in enumerate(RESOURCE_NAMES):
                    raw=camera.read_resource(name)
                    if raw!=package.named_resources[name]:raise ValueError('Current complete menu resource changed')
                    store('resources/'+name,raw)
                    if (index+1)%17==0:print(f'资源读取：{index+1}/68',flush=True)
                loaded=job.loaded(camera,'loaded-source','candidate')
                live=job.probe(camera,'native-source')
                require_same_process(loaded,live)
                if live['before_bases'][10]!=0:raise ValueError('Existing Classic Chrome slot1 is no longer ST')
                for slot in SLOTS:
                    base=next(f for f in fields if f['slot']==slot and len(bytes.fromhex(f['before_ram']))==1)
                    if live['before_bases'][slot+9]!=int(base['before_ram'],16):
                        raise ValueError('Saved and actual selected native base differ')
                final=snapshots(camera,'after')
                preservation={kind:preserved(initial[kind],final[kind],{}) for kind in initial}
        evidence={}
        for name in ('loaded-source/a7cr.diag.runtime.result.private.bin',
                     'loaded-source/a7cr.diag.probe.result.private.bin',
                     'native-source/slot1-a7cr.slot1.bindings.result.private.bin',
                     'native-source/slot1-a7cr.diag.probe.result.private.bin'):
            raw=(attempt/name).read_bytes();evidence[name]={'bytes':len(raw),'sha256':sha(raw)}
        manifest=dict(schema='a7cr-portrait-slots-checkpoint/1',complete=True,model='ILCE-7CR',firmware='2.01',
            utc=datetime.now(timezone.utc).isoformat(),body_binding=package.binding,
            source_package=str(SOURCE.relative_to(ROOT)),source_package_manifest_sha256=sha((SOURCE/'package.private.json').read_bytes()),
            source_program_sha256=SOURCE_HASHES,source_verification=verified,
            copies=['copy-a','copy-b'],files=files,fields=fields,resources=68,
            selected_slots=list(SLOTS),preserve_slots=[1,4,5,6],native_ap_model=live,loaded_source=loaded,
            raw_evidence=evidence,source_probe=package.manifest['native_probe'],
            source_loaded_reader=package.manifest['runtime_readers']['candidate'],preservation=preservation,
            normal_usb_return_confirmed=True,same_physical_volume=copies[0].stat().st_dev==copies[1].stat().st_dev,
            firmware_resources_settings_or_wbi_written=False,only_owned_temporary_readers_executed=True)
        durable_json(destination/'checkpoint.private.json',manifest)
        job.record('PORTRAIT_SLOTS_READONLY_CHECKPOINT_COMPLETE',normal_usb_return_confirmed=True)
        print(json.dumps({'phase':'PORTRAIT_SLOTS_READONLY_CHECKPOINT_COMPLETE','checkpoint':str(destination),
            'copies':2,'resources':68,'native_bases':{str(i):live['before_bases'][i+9] for i in (1,2,3)},
            'camera_persistent_writes':False},ensure_ascii=False,indent=2),flush=True)
        return manifest
    except BaseException as error:
        job.record('stopped_no_retry',error_type=type(error).__name__,error=str(error))
        print('只读检查已停止；保留输出，不要自动重复。',flush=True)
        raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--destination',type=Path,required=True)
    capture(p.parse_args().destination)
