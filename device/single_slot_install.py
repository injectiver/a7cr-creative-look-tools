"""Explicit body-bound slot-1 install/verify/restore host orchestration.

Preparation is separate. This module never prepares a missing worker, downloads
firmware, retries a failed command or restores a whole Backup snapshot. The
agent's preparation task does not authorize running this entry against a camera.
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
from types import SimpleNamespace

from fl23_install import (Job as Fl23Job, Package as Fl23Package, OWNED, PATHS,
                          durable_json, store_private, preserved, invoke as program_invoke)
from single_slot_checkpoint import SlotSession, SLOT_NAMES, invoke_slot_probe, slot_fields
from prepare_six_luts import RESOURCE_NAMES
from diagnose_fl23 import decode_probe, invoke as loaded_invoke
from read_backup import ROOT, backup_sections, private_owner, CP_UNITS
from preflight_fl23 import sha

sys.path.insert(0,str(ROOT/'offline'))
from single_slot_runtime import decode as decode_slot
from single_slot_plan import SLOT_KEYS, BASE_KEY, COMPANION_KEY, MIN_BATTERY
from looktool import devicesettings, nameworker, resources

NAME_TEMPS=frozenset(('a7cr.slot1.names.so','a7c2.names.request','a7c2.names.result'))
ALL_TEMPS=OWNED | SLOT_NAMES | NAME_TEMPS
READY_FLAGS=('ready_for_write','native_worker_simulation_passed','host_flow_tests_passed')
INSTALL_PHASES={'PREPARED_NOT_INSTALLED','PREPARED_OFFLINE_PENDING_REVIEW'}
VERIFY_PHASES={'INSTALLED_PENDING_COLD_START','MACHINE_VERIFIED_PENDING_PHOTOS','COMPLETE',
               'RESTORED_PENDING_COLD_START','RESTORED_MACHINE_VERIFIED_PENDING_PHOTOS','RESTORED_COMPLETE'}
RESTORE_PHASES={'INSTALLED_PENDING_COLD_START','MACHINE_VERIFIED_PENDING_PHOTOS','COMPLETE'}


class PreparationBlocked(ValueError):
    """Required reviewed evidence/artifacts are absent; no live fallback."""


def require_ready(manifest):
    missing=[key for key in READY_FLAGS if manifest.get(key) is not True]
    if missing:raise PreparationBlocked('Write preparation incomplete: '+', '.join(missing))
    if manifest.get('missing_validations'):
        raise PreparationBlocked('Package still declares missing validations')


def _read_json(path):return json.loads(Path(path).read_text())


def _asset(relative, *, workspace=None):
    if not isinstance(relative,str) or Path(relative).is_absolute():raise PreparationBlocked('Use pinned task-relative asset paths')
    path=(ROOT/relative).resolve()
    allowed=(workspace or ROOT/'private').resolve()
    if allowed not in path.parents or not path.is_file() or (ROOT/relative).is_symlink():
        raise PreparationBlocked('Prepared asset escapes private workspace or is missing')
    return path


def _blob(spec, *, workspace=None):
    path=_asset(spec['file'],workspace=workspace);raw=path.read_bytes()
    if not 0<len(raw)<=65536 or len(raw)!=spec['bytes'] or sha(raw)!=spec['sha256']:
        raise PreparationBlocked('Reviewed worker bytes changed')
    return raw


def validate_receipts(manifest,workspace):
    """Bind readiness to actual native artifacts and current host test sources."""
    receipts=manifest.get('validation_receipts',{})
    required={'native_programs','names','host_flow'}
    if not required<=set(receipts):raise PreparationBlocked('Pinned native/name/host validation receipts are missing')
    reports={}
    for kind in required:
        spec=receipts[kind];path=_asset(spec['file'],workspace=workspace);raw=path.read_bytes()
        if sha(raw)!=spec['sha256']:raise PreparationBlocked('Validation receipt digest changed: '+kind)
        report=json.loads(raw)
        if report.get('passed') is not True:raise PreparationBlocked('Validation receipt did not pass: '+kind)
        reports[kind]=report
    for kind,workers in (('native_programs',('program_check','installed_check','cp_stage','ap_stage')),
                         ('names',('names_stage',))):
        actual=reports[kind].get('worker_sha256',{})
        if not isinstance(actual,dict) or any(actual.get(name)!=manifest['workers'][name]['sha256'] for name in workers):
            raise PreparationBlocked('Simulation receipt describes different workers: '+kind)
    programs=reports['native_programs'];names=reports['names']
    for report,field,required_cases in (
        (programs,'actual_full_size_worker_cases',{'baseline-check','cp-install','ap-install','installed-check',
            'restore-ap-first','restore-cp-second','cp-short-write-rolls-back','ap-short-write-rolls-back','wrong-full-source-digest'}),
        (names,'actual_full_resource_cases',{'names-readonly-all68','names-install-all68','names-inverse-all68',
            'names-inverse-reconstruct-after-cleanup','names-stage-write-rollback','names-link-failure-rollback','names-second-commit-rollback'})):
        cases=report.get(field,[])
        if (not isinstance(cases,list) or not required_cases<={row.get('case') for row in cases}
                or any(row.get('passed') is not True for row in cases)):
            raise PreparationBlocked('Required native forward/inverse/failure cases are missing')
    reduced=programs.get('native_hash_algorithm_reduced_fixture_cases',[])
    if not reduced or any(case.get('passed') is not True for case in reduced):
        raise PreparationBlocked('Independent native hashing/window checks are absent')
    if names.get('resource_count')!=68 or names.get('selected_mask')!=1:
        raise PreparationBlocked('Names simulation does not cover the actual 68-resource single-slot scope')
    host=reports['host_flow'];sources=host.get('sources_sha256',{})
    if (type(host.get('tests_run')) is not int or host['tests_run']<=0
            or not {'device/single_slot_install.py','device/test_single_slot_install.py'}<=set(sources)):
        raise PreparationBlocked('Host-flow tests must bind actual runner and test source files')
    from tools.project_paths import source_root
    code_root=source_root().resolve()
    for relative,expected in sources.items():
        path=(code_root/relative).resolve()
        if Path(relative).is_absolute() or code_root not in path.parents or not path.is_file() or sha(path.read_bytes())!=expected:
            raise PreparationBlocked('Actual host source changed after validation: '+relative)


def _manifest(reference):
    if not isinstance(reference,dict):raise PreparationBlocked('Prepared manifest reference is missing')
    if 'manifest' in reference:
        path=_asset(reference['manifest']);raw=path.read_bytes()
        if sha(raw)!=reference.get('manifest_sha256'):raise PreparationBlocked('Prepared manifest digest changed')
        result=json.loads(raw)
        if 'worker' in reference and result['worker']!=reference['worker']:
            raise PreparationBlocked('Manifest worker reference differs')
        return result
    return reference


def _catalog(value):
    if isinstance(value,dict):
        if 'worker' in value and ('read_only' in value or 'manifest' in value):
            yield _manifest(value)
        else:
            for child in value.values():yield from _catalog(child)
    elif isinstance(value,list):
        for child in value:yield from _catalog(child)


class Package:
    """Revalidate the immutable offline package before opening any USB handle."""
    def __init__(self,workspace,*,require_write_ready=False):
        self.root=Path(workspace).resolve()
        if (ROOT/'private').resolve() not in self.root.parents or Path(workspace).is_symlink():
            raise PreparationBlocked('Single-slot task must be in this task private directory')
        self.manifest=_read_json(self.root/'package.private.json');m=self.manifest
        if (m.get('schema')!='a7cr-slot1-offline-installation/1' or m.get('model')!='ILCE-7CR'
                or m.get('version')!='2.01' or m.get('selected_mask')!=1 or m.get('selected_slot')!=1
                or m.get('names')!={'1':'Classic Chrome'} or m.get('no_wholesale_snapshot_restore') is not True):
            raise PreparationBlocked('Unknown single-slot package/scope')
        if require_write_ready:
            require_ready(m);validate_receipts(m,self.root)
        import prepare_single_slot_installation as prep
        material=prep._load_material();self.fl23=prep._load_baseline()
        checkpoint_path=_asset(m['checkpoint']+'/checkpoint.private.json')
        if sha(checkpoint_path.read_bytes())!=m['checkpoint_sha256']:
            raise PreparationBlocked('Fresh checkpoint manifest changed')
        captured=prep._read_checkpoint(checkpoint_path,material,self.fl23)
        if m['body_binding']!=self.fl23.binding:raise PreparationBlocked('Prepared body binding changed')
        self.binding=m['body_binding'];self.checkpoint=captured['checkpoint']
        self.checkpoint_snapshots=captured['snapshots']['before']
        self.fields=m['settings'];self.names={1:'Classic Chrome'}
        if self.fields!=captured['fields'] or len(self.fields)!=9 or {f['key'] for f in self.fields}!=set(SLOT_KEYS):
            raise PreparationBlocked('Selected nine-field plan changed')
        if any(f['before_ram']!=f['before_saved'] for f in self.fields):
            raise PreparationBlocked('Selected checkpoint has unsaved edits; exact restoration is not prepared')
        self.programs={'original':material['original'],'candidate':{}}
        for kind in PATHS:
            spec=m['programs'][kind];path=_asset(spec['candidate_file'],workspace=self.root)
            value=path.read_bytes()
            if value!=material['candidate'][kind]:raise PreparationBlocked('Prepared candidate differs from reviewed program')
            self.programs['candidate'][kind]=value
            old=self.programs['original'][kind];forward,inverse=bytearray(old),bytearray(value);end=0
            for window in spec['windows']:
                at,n=window['offset'],window['bytes'];a,b=bytes.fromhex(window['before_hex']),bytes.fromhex(window['after_hex'])
                if at<end or not 0<n<=4096 or len(a)!=n or len(b)!=n or old[at:at+n]!=a or value[at:at+n]!=b:
                    raise PreparationBlocked('Program inverse window identity differs')
                forward[at:at+n]=b;inverse[at:at+n]=a;end=at+n
            if (bytes(forward)!=value or bytes(inverse)!=old or sha(old)!=spec['source_sha256']
                    or sha(value)!=spec['candidate_sha256'] or len(old)!=spec['bytes']):
                raise PreparationBlocked('Complete program forward/inverse differs')
        self.states={'original':self.programs['original'],
            'cp_only':{'AP':self.programs['original']['AP'],'CP':self.programs['candidate']['CP']},
            'installed':self.programs['candidate']}
        self.audit={'programs':m['programs']}
        self.units=self.fl23.units;self.protected=self.fl23.protected;self.bindings=self.fl23.bindings
        self.resources=captured['resources'];self.named_resources={}
        if set(m['resources'])!=set(RESOURCE_NAMES):raise PreparationBlocked('All 68 exact resource identities are required')
        for name,old in self.resources.items():
            spec=m['resources'][name];changed,plan=resources.rename(old,self.names,list(range(0x0200ab2c,0x0200ab32)))
            path=_asset(spec['target_file'],workspace=self.root)
            if (changed!=path.read_bytes() or resources.inverse(changed,plan)!=old
                    or sha(old)!=spec['before_sha256'] or sha(changed)!=spec['after_sha256']
                    or len(old)!=spec['before_bytes'] or len(changed)!=spec['after_bytes']):
                raise PreparationBlocked('Complete resource/inverse identity differs')
            if (len(old)+4)%512==0 or (len(changed)+4)%512==0:
                raise PreparationBlocked('Resource needs separately validated USB boundary reader')
            self.named_resources[name]=changed
        self.blobs={name:_blob(spec,workspace=self.root if name not in ('wbi_check','wbi_stage') else None)
                    for name,spec in m['workers'].items()}
        needed={'program_check','cp_stage','ap_stage','installed_check','wbi_check','wbi_stage','names_stage'}
        if set(self.blobs)!=needed:raise PreparationBlocked('Native stage worker set differs')
        if m.get('wbi_provenance')!=prep._wbi_provenance(m['workers']):
            raise PreparationBlocked('Retained-image worker simulation provenance changed')
        self.probe=_manifest(m.get('native_probe'))
        if self.probe.get('read_only') is not True or self.probe.get('simulation_passed') is not True:
            raise PreparationBlocked('Actual read-only native model probe simulation is missing')
        _blob(self.probe['worker'])
        self.readers={}
        for direction in ('original','candidate'):
            reader=_manifest(m.get('runtime_readers',{}).get(direction))
            if reader.get('simulation_passed') is not True or not 8<=len(reader.get('spans',[]))<=24:
                raise PreparationBlocked('Loaded-code reader is not prepared/simulated: '+direction)
            _blob(reader['worker']);self.readers[direction]=reader
        self.sync_workers=list(_catalog(m.get('native_sync_workers',{})))
        if not self.sync_workers:raise PreparationBlocked('Native ST/recovery writer catalog is absent')
        # Re-read the immutable compiled-worker receipts, not just inline flags.
        catalog=prep._read_sync_catalog();declared=m['native_sync_workers']
        if any(declared.get(key)!=catalog[key] for key in ('manifest','manifest_sha256','recovery_to_st','recovery_from_st')):
            raise PreparationBlocked('Prepared recovery catalog differs from independently checked evidence')
        for worker in self.sync_workers:
            if worker.get('read_only') is not False or worker.get('simulation_passed') is not True or worker.get('selected_slot')!=1:
                raise PreparationBlocked('Native synchronization catalog lacks actual worker simulation')
            _blob(worker['worker'])
            evidence_path=_asset(worker['simulation_report']);evidence_raw=evidence_path.read_bytes()
            evidence=json.loads(evidence_raw)
            if (sha(evidence_raw)!=worker['simulation_report_sha256'] or evidence.get('passed') is not True
                    or evidence.get('actual_compiled_worker_executed') is not True
                    or evidence.get('worker_sha256')!=worker['worker']['sha256']
                    or len(evidence.get('cases',[]))!=worker.get('simulation_cases')):
                raise PreparationBlocked('Native synchronization worker has no matching actual-binary simulation')
            for guard in worker['audit']['guards']:
                at,n=guard['offset'],guard['bytes'];expected=bytes.fromhex(guard['hex'])
                if any(data['AP'][at:at+n]!=expected for data in self.programs.values()):
                    raise PreparationBlocked('Source/candidate changed a native synchronization function')

    def sync_worker(self,before,target,*,require_current_st):
        matches=[m for m in self.sync_workers if m.get('expected_before')==before and m.get('target')==target
                 and (m.get('require_current_st') is True if require_current_st else True)]
        if not matches:raise PreparationBlocked(f'No simulated native writer for fresh {before}->{target}, global_ST={require_current_st}')
        # Prefer the dedicated initial install worker; stricter recovery workers
        # remain valid only if the native current selection is actually ST.
        return min(matches,key=lambda m:bool(m.get('require_current_st')))


class Session(SlotSession):
    def __init__(self,package,record):
        super().__init__(package,record);self.package=package;self.selected_allowlist={}
        self.expected_usb_serial_sha256=package.binding['usb_serial_sha256']

    def select_temp(self,name):
        if name not in ALL_TEMPS:raise ValueError('Unowned single-slot temporary file')
        status,_=self.temp_command(15,b'\0/tmp/jiritsu/'+name.encode('ascii')+b'\0')
        if status:self.healthy=False;raise ValueError('Temporary selection failed')

    def read_resource(self,name):
        if name not in self.package.resources:raise ValueError('Unowned name resource')
        self.jiritsu(15,b'\0/tmp/jiritsu/../../usr/share/app/'+name.encode('ascii')+b'\0')
        raw=self.jiritsu(17,b'\0\xff\0');decoded=resources.decode(raw)
        if not 5740<=len(raw)<=524288 or decoded['group']!=5 or decoded['count'] not in (2860,2866):
            raise ValueError('Complete name resource layout differs')
        return raw

    def write_selected(self,key,value):
        if key not in SLOT_KEYS or self.selected_allowlist.get(key)!=value:
            raise ValueError('Write outside exact slot1 target allowlist')
        return self.call(f'SLOT1_WRITE2_{key:08x}',self.camera.writeBackup,key,value)

    def save_selected(self):return self.call('SLOT1_SAVE3_02cf',self.camera.saveBackup,0x02cf)


def selected_preservation(before,after,expected,*,native_target=None):
    """Only slot1 fields and native setter's selected thirteen-byte copies."""
    if not set(expected)<=set(SLOT_KEYS):raise ValueError('Settings preservation scope exceeds slot1')
    neutral=[dict(after[0]),after[1]]
    for key,value in expected.items():
        old,new=before[0][key],after[0][key]
        if new.data!=value or new.attr!=old.attr:raise ValueError('Selected field readback differs')
        neutral[0][key]=old
    old,new=before[0].get(COMPANION_KEY),after[0].get(COMPANION_KEY)
    if old is None or new is None:
        if old is not new:raise ValueError('Native selected-setting array disappeared')
    elif (old.data,old.attr)!=(new.data,new.attr):
        if (native_target is None or old.attr!=0xc0 or new.attr!=old.attr or len(old.data)!=13 or len(new.data)!=13
                or any(a!=b and b!=native_target for a,b in zip(old.data,new.data))):
            raise ValueError('Native setter changed an unreviewed companion byte')
        neutral[0][COMPANION_KEY]=old
    return preserved(before,neutral,{})


def invoke_slot_writer(camera,manifest,folder,record):
    if manifest.get('read_only') is not False or manifest.get('simulation_passed') is not True:
        raise PreparationBlocked('Native writer was not individually simulated')
    blob=_blob(manifest['worker'])
    for name in sorted(ALL_TEMPS):
        if camera.read_temp(name,True) is not None:raise ValueError('Preserve existing native temporary state')
    camera.check_preload();expected={'a7cr.slot1-staged.so':blob,'libJit.so':blob}
    camera.write_temp('a7cr.slot1-staged.so',blob,expected)
    if camera.read_temp('a7cr.slot1-staged.so')!=blob:raise ValueError('Native writer staging changed')
    record('slot1_native_sync_intent',worker_sha256=sha(blob),before=manifest['expected_before'],target=manifest['target'])
    try:
        camera.write_temp('libJit.so',blob,expected)
        for name in ('a7cr.diag.probe.result','a7cr.slot1.bindings.result'):
            expected[name]=camera.read_temp(name);store_private(folder/(name+'.private.bin'),expected[name])
        probe=decode_probe(expected['a7cr.diag.probe.result'])
        result=decode_slot(expected['a7cr.slot1.bindings.result'],read_only=False,
            expected_before=manifest['expected_before'],target=manifest['target'],require_current_st=manifest['require_current_st'])
        if probe['status'] or probe['cleanup'] or (probe['base'],probe['pid'])!=(result['base'],result['pid']):
            raise ValueError('Native writer process identity differs')
    except BaseException:
        camera.healthy=False;raise
    record('slot1_native_sync_returned',runtime=result)
    for name in ('libJit.so','a7cr.slot1.bindings.result','a7cr.diag.probe.result','a7cr.slot1-staged.so'):
        camera.remove_temp(name,expected)
    record('slot1_native_sync_cleanup_verified')
    return result


class Job(Fl23Job):
    def folder(self,tag):
        folder=self.attempt/tag;folder.mkdir(exist_ok=False);private_owner(folder,True);return folder

    def snapshots(self,camera,tag):
        result=super().snapshots(camera,tag)
        for sections in result.values():
            for key in CP_UNITS:
                expected=self.package.fl23.units['candidate'].get(key,self.package.fl23.protected.get(key))
                if sections[1][key].data!=expected:raise ValueError('Current FL23 CP color/calibration changed')
            for key,value in self.package.fl23.bindings['candidate'].items():
                if sections[0][key].data!=value:raise ValueError('Original FL23 entry binding changed')
        return result

    def probe(self,camera,tag):
        result=invoke_slot_probe(camera,self.package.probe,self.folder(tag),self.record)
        if type(result['current']) is not int or not 0<=result['current']<=17:
            raise ValueError('Unknown native current selector')
        return result

    def loaded(self,camera,tag,direction,*,allow_known_loaded=False):
        # Recovery can precede cold start, or follow a known AP inverse. Read
        # all 16 candidate spans and accept a coherent source OR candidate AP,
        # never arbitrary per-span mixing. Disk still must match its exact state.
        manifest=self.package.readers['candidate' if allow_known_loaded else direction]
        if allow_known_loaded and len(manifest['spans'])!=16:
            raise PreparationBlocked('Recovery requires the complete reviewed 16-span reader')
        blob=_blob(manifest['worker'])
        result=loaded_invoke(camera,blob,manifest['spans'],self.package,self.folder(tag),self.record)
        if not result['ok'] or len(result.get('spans',[]))!=len(manifest['spans']):
            raise ValueError('Loaded AP reader failed or omitted a reviewed span')
        possible={'original','candidate'} if allow_known_loaded else {direction}
        for span,item in zip(manifest['spans'],result['spans']):
            at,n=span['offset'],span['bytes']
            expected=self.package.programs[direction]['AP'][at:at+n]
            if bytes.fromhex(item['disk_hex'])!=expected:
                raise ValueError('Actual disk AP spans changed after complete program readback')
            live=bytes.fromhex(item['loaded_hex'])
            possible &= {state for state in possible if live==self.package.programs[state]['AP'][at:at+n]}
            if not possible:raise ValueError('Actual loaded AP is mixed or outside the known source/candidate states')
        result['accepted_loaded_state']=sorted(possible)
        return result

    def titles(self,camera,*,named=None):
        found=[]
        for name,old in self.package.resources.items():
            raw=camera.read_resource(name);new=self.package.named_resources[name]
            if raw not in (old,new):
                store_private(self.attempt/(name+'.unexpected.private.bin'),raw)
                raise ValueError('Resource has unknown or later-modified bytes')
            label='original' if raw==old else 'named';found.append(label)
            if named is not None and raw!=(new if named else old):raise ValueError('Complete resource readback differs')
        states=set(found)
        if len(states)!=1:raise ValueError('Mixed name-resource transaction requires inspection')
        result=states.pop();self.record('all_68_resource_bytes_verified',state=result);return result

    def names_native(self,camera,mode):
        if mode not in (0,1,2):raise ValueError('No resource cleanup before explicit acceptance')
        blob=self.package.blobs['names_stage'];expected={'a7cr.slot1.names.so':blob,'libJit.so':blob,
            'a7c2.names.request':struct.pack('<8sII',b'A7NAM001',mode,0)}
        for name in sorted(ALL_TEMPS):
            if camera.read_temp(name,True) is not None:raise ValueError('Preserve existing native state before names')
        camera.check_preload()
        for name in ('a7cr.slot1.names.so','a7c2.names.request'):
            camera.write_temp(name,expected[name],expected)
            if camera.read_temp(name)!=expected[name]:raise ValueError('Names staging readback differs')
        self.record('slot1_names_invocation_intent',mode=mode)
        try:
            camera.write_temp('libJit.so',blob,expected)
            raw=camera.read_temp('a7c2.names.result');store_private(self.folder('names-'+str(mode))/'result.private.bin',raw)
            parsed=nameworker.validate(raw,mode,self.package.manifest['names_build'])
        except BaseException:
            camera.healthy=False;raise
        expected['a7c2.names.result']=raw
        self.record('slot1_names_invocation_returned',mode=mode,report=parsed)
        for name in ('libJit.so','a7c2.names.result','a7c2.names.request','a7cr.slot1.names.so'):
            camera.remove_temp(name,expected)
        self.record('slot1_names_cleanup_verified',mode=mode)
        return parsed

    def write_fields(self,camera,before,desired,tag):
        if not set(desired)<=set(SLOT_KEYS):raise ValueError('Selected write plan exceeds slot1')
        devicesettings.require_save_preserves_unsaved(before['memory'],before['flash'],set(desired))
        for key in desired:
            if before['memory'][0][key].data!=before['flash'][0][key].data:
                raise ValueError('Preserve unsaved selected user edits')
        camera.selected_allowlist=dict(desired);changed=False
        try:
            for key,value in desired.items():
                fresh=camera.call(f'SLOT1_READ2_{key:08x}',camera.camera.readBackup,key)
                if fresh!=before['memory'][0][key].data:raise ValueError('Selected value raced before write')
                if fresh!=value:
                    self.record('slot1_setting_write_intent',key=key,target=value.hex())
                    camera.write_selected(key,value)
                    if camera.call(f'SLOT1_READBACK2_{key:08x}',camera.camera.readBackup,key)!=value:
                        raise ValueError('Selected direct readback differs')
                    self.record('slot1_setting_readback_verified',key=key);changed=True
            if changed:camera.save_selected()
        finally:camera.selected_allowlist={}
        after=self.snapshots(camera,tag)
        target=desired[BASE_KEY][0] if BASE_KEY in desired else None
        for source in before:selected_preservation(before[source],after[source],desired,native_target=target)
        return after

    def reprobe_after_saved(self,camera,previous,allowed,tag):
        fresh=self.probe(camera,tag)
        if (fresh['pid'],fresh['base'],fresh['boot_id'],fresh['current'])!=(previous['pid'],previous['base'],previous['boot_id'],previous['current']):
            raise ValueError('Native process/current changed during selected setting staging')
        for index,(old,new) in enumerate(zip(previous['before_bases'],fresh['before_bases'])):
            if (index==10 and new not in allowed) or (index!=10 and new!=old):
                raise ValueError('Saved setting stage caused foreign native model drift')
        return fresh

    def already_coherent(self,camera,before,probe,target,tag):
        if probe['before_bases'][10]!=target or probe['current']!=0:
            raise ValueError('Native base is not independently coherent with saved target')
        after=self.snapshots(camera,tag)
        for source in before:selected_preservation(before[source],after[source],{BASE_KEY:bytes([target])},native_target=target)
        self.record('native_base_already_coherent_no_writer',target=target,runtime=probe)
        return after,probe

    def sync(self,camera,before,probe,worker,tag):
        if worker['require_current_st'] and probe['current']!=0:
            raise ValueError('Owner must select global ST before recovery writes')
        if probe['before_bases'][10]!=worker['expected_before']:
            raise ValueError('Fresh native before-value does not match worker CAS')
        result=invoke_slot_writer(camera,worker,self.folder(tag+'-native'),self.record)
        if ((result['pid'],result['base'],result['boot_id'])!=(probe['pid'],probe['base'],probe['boot_id'])
                or result['before_bases']!=probe['before_bases'] or result['current']!=probe['current']):
            raise ValueError('Native before/model/process changed after fresh probe')
        after=self.snapshots(camera,tag+'-after')
        target=worker['target']
        for source in before:selected_preservation(before[source],after[source],{BASE_KEY:bytes([target])},native_target=target)
        return after,result

    def invalidate(self,camera,loaded):
        if loaded['image_mode']=='0\n':
            self.record('wbi_already_mode0_no_write');return
        if loaded['image_mode']!='2\n':raise ValueError('Unknown retained-image mode')
        self.native(camera,'wbi_stage',1)

    def install(self,camera):
        self.body(camera);self.program_state(camera,'initial','original');self.titles(camera,named=False)
        initial=self.snapshots(camera,'initial')
        if slot_fields(self.package.programs['original']['AP'],initial['memory'],initial['flash'])!=self.package.fields:
            raise ValueError('Selected slot/ST source changed since body-bound preparation')
        devicesettings.require_save_preserves_unsaved(initial['memory'],initial['flash'],set(SLOT_KEYS))
        loaded=self.loaded(camera,'loaded-before','original');probe=self.probe(camera,'native-before')
        if loaded['boot_id']!=probe['boot_id']:raise ValueError('Boot changed within preflight')
        if probe['current']!=0:raise ValueError('Owner must select global ST before single-slot installation')
        # A saved-property write can either leave the AP model unchanged or
        # already make it ST. Prepare both CAS outcomes before any mutation.
        workers={value:self.package.sync_worker(value,0,require_current_st=True)
                 for value in {probe['before_bases'][10],0}}
        self.native(camera,'program_check',0);self.names_native(camera,0)
        if loaded['image_mode']=='2\n':self.native(camera,'wbi_check',0)
        elif loaded['image_mode']!='0\n':raise ValueError('Unknown retained-image state before writes')
        self.phase('DEVICE_PREFLIGHT_PASSED')
        desired={f['key']:bytes.fromhex(f['after']) for f in self.package.fields}
        staged=self.write_fields(camera,initial,desired,'saved-st-before-sync')
        fresh=self.reprobe_after_saved(camera,probe,{probe['before_bases'][10],0},'native-after-saved-st')
        staged,synced=self.sync(camera,staged,fresh,workers[fresh['before_bases'][10]],'sync-st-before-programs')
        self.phase('SLOT1_SAVED_AND_NATIVE_ST_VERIFIED')
        self.native(camera,'cp_stage',1);self.program_state(camera,'after-cp','cp_only')
        self.names_native(camera,1);self.titles(camera,named=True)
        self.native(camera,'ap_stage',1);self.program_state(camera,'after-ap','installed')
        final=self.snapshots(camera,'install-final')
        for source in final:preserved(staged[source],final[source],{})
        self.invalidate(camera,loaded)
        return {'before_boot_id':loaded['boot_id'],'native_st':synced,
                'phase':'INSTALLED_PENDING_COLD_START','physical_acceptance':False}

    def verify(self,camera,*,restored=False,physical_accepted=False,before_boot_id=None):
        self.body(camera);direction='original' if restored else 'candidate'
        self.program_state(camera,'verify','original' if restored else 'installed');self.titles(camera,named=not restored)
        before=self.snapshots(camera,'verify-before');loaded=self.loaded(camera,'verify-loaded',direction)
        probe=self.probe(camera,'verify-native')
        if not before_boot_id or loaded['boot_id']==before_boot_id:
            raise ValueError('A new kernel boot has not been established; do not reinstall')
        if loaded['boot_id']!=probe['boot_id']:raise ValueError('Native/model verification boot changed')
        saved_base=before['flash'][0][BASE_KEY].data
        if (len(saved_base)!=1 or saved_base[0]>11 or before['memory'][0][BASE_KEY].data!=saved_base
                or probe['before_bases'][10]!=saved_base[0]):
            raise ValueError('Saved, Backup RAM and actual native slot1 bases do not agree')
        if not restored and saved_base!=b'\0':
            raise ValueError('Imported slot is not ST in saved and actual native model')
        after=self.snapshots(camera,'verify-after')
        for source in before:preserved(before[source],after[source],{})
        prefix='RESTORED_' if restored else ''
        phase=prefix+('COMPLETE' if physical_accepted else 'MACHINE_VERIFIED_PENDING_PHOTOS')
        return {'phase':phase,'loaded_ap':loaded,'native_model':probe,'physical_acceptance':physical_accepted,
                'before_boot_id':before_boot_id,'firmware_settings_or_wbi_written':False,
                'owned_resource_backup_links_retained':True}

    def restore(self,camera):
        self.body(camera);state=self.program_state(camera,'restore-initial');name_state=self.titles(camera)
        initial=self.snapshots(camera,'restore-initial');probe=self.probe(camera,'restore-native-before')
        if probe['current']!=0:raise ValueError('Owner must select global ST before any recovery setting/program write')
        loaded=self.loaded(camera,'restore-loaded-before','candidate' if state=='installed' else 'original',allow_known_loaded=True)
        if loaded['boot_id']!=probe['boot_id']:raise ValueError('Boot changed during recovery preflight')
        for key in SLOT_KEYS:
            if initial['memory'][0][key].data!=initial['flash'][0][key].data:
                raise ValueError('Recovery must preserve unsaved selected user edits')
        devicesettings.require_save_preserves_unsaved(initial['memory'],initial['flash'],set(SLOT_KEYS))
        desired={};kept=[]
        for field in self.package.fields:
            key=field['key'];value=initial['memory'][0][key].data
            if value==bytes.fromhex(field['after']):desired[key]=bytes.fromhex(field['before_saved'])
            else:desired[key]=value;kept.append(key)
        if len(desired[BASE_KEY])!=1 or desired[BASE_KEY][0]>11:raise ValueError('Unsupported native recovery base')
        # Check BOTH writers before first persistent setting mutation.
        to_st={value:self.package.sync_worker(value,0,require_current_st=True)
               for value in {probe['before_bases'][10],0}}
        from_st=self.package.sync_worker(0,desired[BASE_KEY][0],require_current_st=True)
        if loaded['image_mode']=='2\n':self.native(camera,'wbi_check',0)
        elif loaded['image_mode']!='0\n':raise ValueError('Unknown retained-image state before recovery')
        staged=self.write_fields(camera,initial,{BASE_KEY:b'\0'},'restore-saved-st')
        fresh=self.reprobe_after_saved(camera,probe,{probe['before_bases'][10],0},'restore-native-after-saved-st')
        staged,synced=self.sync(camera,staged,fresh,to_st[fresh['before_bases'][10]],'restore-native-st')
        if state=='installed':self.native(camera,'ap_stage',2);self.program_state(camera,'restore-after-ap','cp_only');state='cp_only'
        if state=='cp_only':self.native(camera,'cp_stage',2);self.program_state(camera,'restore-after-cp','original')
        if name_state=='named':self.names_native(camera,2);self.titles(camera,named=False)
        before_restore=self.snapshots(camera,'restore-selected-before')
        before_native=self.probe(camera,'restore-native-before-saved-original-base')
        if before_native['before_bases'][10]!=0 or before_native['current']!=0:
            raise ValueError('Native deactivation changed before original recipe restore')
        restored=self.write_fields(camera,before_restore,desired,'restore-selected-saved')
        # A fresh read-only native report is mandatory; previous reports cannot
        # stand in for state after AP/CP/resource transitions.
        target=desired[BASE_KEY][0]
        fresh=self.reprobe_after_saved(camera,before_native,{0,target},'restore-native-before-original-base')
        if fresh['before_bases'][10]==target:
            restored,model=self.already_coherent(camera,restored,fresh,target,'restore-native-already-coherent')
        else:restored,model=self.sync(camera,restored,fresh,from_st,'restore-native-original-base')
        self.program_state(camera,'restore-final','original');self.titles(camera,named=False)
        self.invalidate(camera,loaded)
        return {'phase':'RESTORED_PENDING_COLD_START','before_boot_id':loaded['boot_id'],
                'preserved_later_user_fields':[f'{key:08x}' for key in kept],
                'native_restored_base':model,'physical_recovery_verified':False}


def validate_command_state(command,state):
    phase=state.get('phase','')
    allowed=INSTALL_PHASES if command=='install' else VERIFY_PHASES if command=='verify' else RESTORE_PHASES
    if phase not in allowed:raise PreparationBlocked('Task phase requires inspection; never replay an unknown write: '+phase)


def guard_existing_write_attempts(workspace):
    """A process crash must not leave a nominally PREPARED state reusable."""
    for folder in sorted(Path(workspace).iterdir()):
        if not folder.is_dir() or not folder.name.startswith(('install-','restore-')):continue
        path=folder/'events.private.json'
        if not path.is_file():raise PreparationBlocked('An earlier write attempt lacks durable outcome evidence')
        events=_read_json(path)
        last=events[-1] if isinstance(events,list) and events else {}
        if last.get('phase')!='single_slot_command_complete' or last.get('normal_usb_return_confirmed') is not True:
            raise PreparationBlocked('Earlier write attempt needs inspection; do not replay or reauthenticate it: '+folder.name)


def run(workspace,command,*,battery_percent=None,physical_accepted=False,session_factory=Session):
    if command not in ('install','verify','restore'):raise ValueError('Unknown explicit command')
    if command!='verify' and (type(battery_percent) is not int or not MIN_BATTERY<=battery_percent<=100):
        raise PreparationBlocked('Fresh on-camera battery confirmation must be at least 75 percent')
    package=Package(workspace,require_write_ready=command!='verify')
    state=_read_json(package.root/'state.private.json');validate_command_state(command,state)
    guard_existing_write_attempts(package.root)
    if os.geteuid()!=0:raise PermissionError('Camera USB capture requires sudo in the owner terminal')
    os.umask(0o077)
    with (ROOT/'private/device.lock').open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Re-read under lock so a concurrent host cannot advance this job.
        if _read_json(package.root/'state.private.json')!=state:raise PreparationBlocked('Task state changed before lock')
        guard_existing_write_attempts(package.root)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        attempt=package.root/(command+'-'+stamp);attempt.mkdir(exist_ok=False);private_owner(attempt,True)
        job=Job(package,attempt)
        try:
            job.record('single_slot_command_started',command=command,battery_percent=battery_percent)
            with session_factory(package,job.record) as camera:
                if command=='install':result=job.install(camera)
                elif command=='restore':result=job.restore(camera)
                else:result=job.verify(camera,restored=state['phase'].startswith('RESTORED_'),
                    physical_accepted=physical_accepted,before_boot_id=state.get('before_boot_id'))
            # Session.__exit__ must establish ordinary USB before completion.
            durable_json(attempt/'result.private.json',result)
            job.phase(result['phase'],**{k:v for k,v in result.items() if k!='phase'})
            job.record('single_slot_command_complete',command=command,normal_usb_return_confirmed=True)
            return result
        except BaseException as error:
            if command=='verify':
                # Read-only failure does not erase the last installed/restored state.
                job.record('readonly_verify_stopped_no_retry',error_type=type(error).__name__,error=str(error))
            else:job.phase('STOPPED_INSPECTION_REQUIRED',error_type=type(error).__name__,error=str(error))
            raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--command',choices=('install','verify','restore'),required=True)
    parser.add_argument('--battery-percent',type=int)
    parser.add_argument('--physical-accepted',action='store_true',help='Owner actually checked preview/new photos/playback and preserved native/other-slot looks')
    args=parser.parse_args()
    result=run(args.workspace,args.command,battery_percent=args.battery_percent,physical_accepted=args.physical_accepted)
    print(json.dumps(result,ensure_ascii=False,indent=2))
