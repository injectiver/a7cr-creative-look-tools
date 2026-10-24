"""Prepare body-bound slot-1 assets entirely offline; never an install command.

A completed, separately captured read-only checkpoint is mandatory. This
module does not acquire a checkpoint, authenticate USB, fabricate live state,
or infer native model values from saved Backup properties.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path[:0] = [str(ROOT/'offline'), str(ROOT/'device'), str(ROOT/'research/repos/a7c2-fl23-research/src/looks')]
CANDIDATE = ROOT/'private/single-slot-candidate'
BASELINE = ROOT/'private/install/fl23'
LABEL_IDS = list(range(0x0200ab2c, 0x0200ab32))
SELECTED_KEYS = {0x02cf0cd0, *range(0x02cf0cf0, 0x02cf0df0, 0x20)}
CP_UNITS = {0x02a40000:4608, 0x02a40001:8192, 0x02a40002:768, 0x02a4000d:28672}
SCHEMA = 'a7cr-slot1-offline-installation/1'


def sha(raw):return hashlib.sha256(raw).hexdigest()

def _read_json(path):return json.loads(Path(path).read_text())

def _private_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n');path.chmod(0o600)

def _relative(path):
    path=Path(path).resolve()
    try:return str(path.relative_to(ROOT))
    except ValueError:raise ValueError('Preparation assets must remain inside this task')


def _resource_names():
    from looktool import nameworker
    return tuple(nameworker.filenames())


def _load_baseline():
    from fl23_install import Package
    return Package(BASELINE)


def _decode_snapshot(raw):
    from read_backup import backup_sections
    return backup_sections(raw)


def _derive_fields(ap, ram, saved):
    from single_slot_checkpoint import slot_fields
    return slot_fields(ap, ram, saved)


def _snapshot_preservation(before, after):
    from fl23_install import preserved
    return preserved(before, after, {})


def _unsaved_preservation(ram, saved, keys):
    from looktool.devicesettings import require_save_preserves_unsaved
    return require_save_preserves_unsaved(ram, saved, keys)


def _load_material():
    from single_slot_candidate import EXPECTED, verify_native_paths
    manifest=_read_json(CANDIDATE/'candidate.private.json')
    ownership=_read_json(CANDIDATE/'source-ownership.private.json')
    loading=_read_json(CANDIDATE/'loading-proof.private.json')
    if (manifest.get('schema')!='a7cr-single-slot-candidate/1' or manifest.get('selected_mask')!=1
            or manifest.get('names')!={'1':'Classic Chrome'} or manifest.get('camera_accessed') is not False
            or not manifest.get('native_instruction_tests_passed') or not manifest.get('inverse_full_files_exact')
            or not ownership.get('source_boundary_and_reference_audit_passed') or loading.get('passed') is not True):
        raise ValueError('Single-slot offline candidate/source ownership checks incomplete')
    original={k:(BASELINE/'payload'/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    candidate={k:(CANDIDATE/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    for kind in original:
        spec=manifest['programs'][kind]
        if (sha(original[kind])!=EXPECTED[kind] or sha(original[kind])!=spec['source_sha256']
                or sha(candidate[kind])!=spec['candidate_sha256'] or len(candidate[kind])!=spec['bytes']
                or ownership['source_program_sha256'][kind]!=sha(original[kind])
                or ownership['candidate_program_sha256'][kind]!=sha(candidate[kind])):
            raise ValueError('Single-slot program/review identity differs')
    if loading.get('candidate_cp_sha256')!=sha(candidate['CP']):
        raise ValueError('Candidate CP loader/bootstrap proof differs')
    # Repeat actual candidate CPU paths, do not trust a manually toggled flag.
    native=verify_native_paths(original, candidate, manifest)
    return {'original':original,'candidate':candidate,'manifest':manifest,'ownership':ownership,'native_paths':native,
            'manifest_sha256':sha((CANDIDATE/'candidate.private.json').read_bytes()),
            'ownership_sha256':sha((CANDIDATE/'source-ownership.private.json').read_bytes()),
            'loading_sha256':sha((CANDIDATE/'loading-proof.private.json').read_bytes())}


def _checkpoint_header(checkpoint):
    if (checkpoint.get('schema')!='a7cr-slot1-readonly-checkpoint/1' or checkpoint.get('complete') is not True
            or checkpoint.get('model')!='ILCE-7CR' or checkpoint.get('firmware')!='2.01'
            or checkpoint.get('normal_usb_return_confirmed') is not True
            or checkpoint.get('firmware_resources_settings_or_wbi_written') is not False
            or checkpoint.get('only_owned_temporary_readers_executed') is not True
            or checkpoint.get('installation_prepared') is not False or checkpoint.get('resources')!=68
            or checkpoint.get('copies')!=['copy-a','copy-b']):
        raise ValueError('Require a complete, cleanly exited, read-only slot1 checkpoint')
    live=checkpoint.get('native_ap_model');loaded=checkpoint.get('loaded_fl23')
    if not isinstance(live,dict) or not isinstance(loaded,dict):
        raise ValueError('Fresh native AP model and loaded FL23 reports are required')
    before,after=live.get('before_bases'),live.get('after_bases')
    if (live.get('read_only') is not True or live.get('only_slot1_may_change') is not True
            or not isinstance(before,list) or len(before)!=18 or after!=before
            or any(type(value) is not int or not 0<=value<=11 for value in before)
            or live.get('changed_mask')!=0 or live.get('current')!=live.get('after_current')
            or type(live.get('current')) is not int or not 0<=live['current']<=17
            or type(live.get('pid')) is not int or live['pid']<=0
            or type(live.get('base')) is not int or live['base']<=0):
        raise ValueError('Native AP probe is absent, writable, changed, or malformed')
    boot=live.get('boot_id','')
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n',boot) is None:
        raise ValueError('Native checkpoint boot identity is missing')
    if (loaded.get('ok') is not True or loaded.get('all_loaded_ap_spans_match_candidate') is not True
            or loaded.get('boot_id')!=boot or loaded.get('pid')!=live['pid'] or loaded.get('base')!=live['base']):
        raise ValueError('Native model and loaded baseline do not describe the same current AP')
    return live


def _decode_live_evidence(folder,baseline,checkpoint):
    from diagnose_fl23 import decode_probe,decode_runtime
    from single_slot_runtime import decode as decode_slot
    reader_path=ROOT/'private/runtime-diagnostic/runtime.private.json'
    _reader_reference(reader_path)
    reader=_read_json(reader_path)
    filenames={'loaded_probe':'a7cr.diag.probe.result.private.bin',
               'loaded_runtime':'a7cr.diag.runtime.result.private.bin',
               'slot_probe':'slot1-a7cr.diag.probe.result.private.bin',
               'slot_runtime':'slot1-a7cr.slot1.bindings.result.private.bin'}
    raw={role:(Path(folder)/'evidence'/name).read_bytes() for role,name in filenames.items()}
    loaded_probe=decode_probe(raw['loaded_probe']);slot_probe=decode_probe(raw['slot_probe'])
    loaded=decode_runtime(raw['loaded_runtime'],reader['spans'],baseline)
    native=decode_slot(raw['slot_runtime'],read_only=True)
    if loaded!=checkpoint['loaded_fl23'] or native!=checkpoint['native_ap_model']:
        raise ValueError('Checkpoint native/loaded JSON differs from original binary reports')
    for probe,report in ((loaded_probe,loaded),(slot_probe,native)):
        if probe['status'] or probe['cleanup'] or probe['pid']!=report['pid'] or probe['base']!=report['base']:
            raise ValueError('Raw probe and runtime reports have different process/outcome')
    if (loaded['pid']!=native['pid'] or loaded['base']!=native['base'] or loaded['boot_id']!=native['boot_id']
            or not loaded['ok'] or not loaded['all_loaded_ap_spans_match_candidate']
            or any(item['loaded_state']!='candidate' or item['disk_state']!='candidate' for item in loaded['spans'])):
        raise ValueError('Raw loaded code/native base evidence is not the same current FL23 candidate')
    return {'files':{filenames[role]:{'bytes':len(data),'sha256':sha(data)} for role,data in raw.items()},
            'loaded_reader_manifest_sha256':sha(reader_path.read_bytes()),'binary_reports_redecoded':True}


def _read_checkpoint(path, material, baseline):
    path=Path(path).resolve()
    if path.is_dir():path=path/'checkpoint.private.json'
    raw=path.read_bytes();checkpoint=json.loads(raw)
    live=_checkpoint_header(checkpoint)
    if checkpoint.get('body_binding')!=baseline.binding:
        raise ValueError('Checkpoint body binding differs from verified FL23 installation')
    names=_resource_names()
    expected={'AP.bin','CP.bin',*(f'{tag}-{kind}.bin' for tag in ('before','after') for kind in ('memory','flash')),
              *(f'{tag}-{kind}-cp-{key:08x}.bin' for tag in ('before','after') for kind in ('memory','flash') for key in CP_UNITS),
              *('resources/'+name for name in names)}
    if set(checkpoint.get('files',{}))!=expected:
        raise ValueError('Checkpoint is missing complete programs, snapshots, CP units or all 68 resources')
    copies=[path.parent/name for name in checkpoint['copies']]
    if any(p.is_symlink() for p in copies) or copies[0].resolve()==copies[1].resolve():
        raise ValueError('Checkpoint copies must be independent directories')
    files={}
    for name in sorted(expected):
        specs=checkpoint['files'][name]
        if type(specs.get('bytes')) is not int or specs['bytes']<=0 or not re.fullmatch('[0-9a-f]{64}',specs.get('sha256','')):
            raise ValueError('Invalid checkpoint file identity')
        values=[];inodes=[]
        for copy in copies:
            p=copy/name
            if p.is_symlink() or not p.is_file() or copy.resolve() not in p.resolve().parents:
                raise ValueError('Checkpoint file escaped its independent copy')
            stat=p.stat();inodes.append((stat.st_dev,stat.st_ino))
            data=p.read_bytes()
            if len(data)!=specs['bytes'] or sha(data)!=specs['sha256']:
                raise ValueError('Checkpoint file size/digest differs: '+name)
            values.append(data)
        if inodes[0]==inodes[1] or values[0]!=values[1]:
            raise ValueError('Checkpoint copies share an inode or differ: '+name)
        files[name]=values[0]
    for kind in ('AP','CP'):
        if files[kind+'.bin']!=material['original'][kind]:
            raise ValueError('Checkpoint programs differ from verified FL23 source')
    snapshots={}
    for tag in ('before','after'):
        snapshots[tag]={}
        for kind in ('memory','flash'):
            decoded=_decode_snapshot(files[f'{tag}-{kind}.bin'])
            serial=decoded[0][0x00e70003].data
            if len(serial)!=4 or sha(serial.hex().encode('ascii'))!=baseline.binding['ap_serial_sha256']:
                raise ValueError('Snapshot body identity differs')
            for key,n in CP_UNITS.items():
                value=decoded[1][key].data
                expected_value=baseline.units['candidate'].get(key,baseline.protected.get(key))
                if len(value)!=n or value!=files[f'{tag}-{kind}-cp-{key:08x}.bin'] or value!=expected_value:
                    raise ValueError('Protected CP unit does not match complete snapshots/current FL23 baseline')
            snapshots[tag][kind]=decoded
    before,after=snapshots['before'],snapshots['after']
    preservation={kind:_snapshot_preservation(before[kind],after[kind]) for kind in before}
    fields=_derive_fields(files['AP.bin'],before['memory'],before['flash'])
    if (len(fields)!=9 or {f['key'] for f in fields}!=SELECTED_KEYS or fields!=checkpoint.get('fields')
            or any(f.get('slot')!=1 for f in fields)):
        raise ValueError('Slot1 nine-field plan differs from fresh source descriptors/snapshots')
    for field in fields:
        n=1 if field['key']==0x02cf0cd0 else 4
        if any(len(bytes.fromhex(field[k]))!=n for k in ('before_ram','before_saved','after')):
            raise ValueError('Selected slot field size differs')
    if any(field['before_ram']!=field['before_saved'] for field in fields):
        raise ValueError('Selected slot unsaved changes require a separately reviewed replay protocol')
    _unsaved_preservation(before['memory'],before['flash'],SELECTED_KEYS)
    # A native setter is allowed to synchronize AP, not to infer its before value.
    if not 0<=live['before_bases'][10]<=11:
        raise ValueError('Fresh native slot1 before value is missing')
    events=_read_json(path.parent/'evidence/events.private.json')
    required={'slot1_readonly_probe_cleanup_verified','runtime_readonly_cleanup_verified','normal_usb_returned','SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE'}
    phases={row.get('phase') for row in events}
    if (not events or events[-1].get('phase')!='SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE'
            or not required<=phases or any('stopped' in str(p).lower() for p in phases)):
        raise ValueError('Checkpoint diagnostic cleanup/normal USB completion evidence is incomplete')
    raw_evidence=_decode_live_evidence(path.parent,baseline,checkpoint)
    return {'path':path,'raw':raw,'checkpoint':checkpoint,'files':files,'snapshots':snapshots,'raw_evidence':raw_evidence,
            'fields':fields,'preservation':preservation,'native':live,'resources':{name:files['resources/'+name] for name in names}}


def _normalized_programs(material):
    original,candidate=material['original'],material['candidate']
    programs={};all_windows=[]
    for chip,kind in enumerate(('AP','CP')):
        source=material['manifest']['programs'][kind]
        forward,inverse=bytearray(original[kind]),bytearray(candidate[kind]);rows=[];end=0
        for w in sorted(source['windows'],key=lambda item:item['offset']):
            old,new=bytes.fromhex(w['before_hex']),bytes.fromhex(w['after_hex']);at=w['offset']
            if (type(at) is not int or at<end or not old or len(old)!=len(new) or w['bytes']!=len(old)
                    or original[kind][at:at+len(old)]!=old or candidate[kind][at:at+len(new)]!=new):
                raise ValueError('Candidate window source/target/order differs')
            for offset in range(0,len(old),4096):
                a,b=old[offset:offset+4096],new[offset:offset+4096]
                rows.append({'chip':chip,'offset':at+offset,'bytes':len(a),'before_hex':a.hex(),'after_hex':b.hex(),'purpose':w['purpose']})
            forward[at:at+len(old)]=new;inverse[at:at+len(old)]=old;end=at+len(old)
        if bytes(forward)!=candidate[kind] or bytes(inverse)!=original[kind]:
            raise ValueError('Complete candidate/inverse differs')
        programs[kind]={**{key:source[key] for key in ('source_sha256','candidate_sha256','bytes')},'windows':rows}
        all_windows.extend(rows)
    return programs,all_windows


def _compile_program_workers(output,material,windows):
    from build_native_workers import compile_worker,manifest_header,source
    initial=[sha(material['original'][kind]) for kind in ('AP','CP')]
    final=[sha(material['candidate'][kind]) for kind in ('AP','CP')]
    middle=[initial[0],final[1]];sizes=[len(material['original'][kind]) for kind in ('AP','CP')]
    inverse=[{**w,'before_hex':w['after_hex'],'after_hex':w['before_hex']} for w in windows]
    workers={}
    for name,a,b,rows,read_only in (
            ('program_check',initial,final,windows,True),
            ('cp_stage',initial,middle,[w for w in windows if w['chip']==1],False),
            ('ap_stage',middle,final,[w for w in windows if w['chip']==0],False),
            ('installed_check',final,initial,inverse,True)):
        workers[name]=compile_worker(output/'workers'/name,name,source('program',read_only),manifest_header(a,b,sizes,rows))
    return workers


def _prepare_names(output,checkpoint,material):
    from looktool import nameworker,resources
    for name,raw in checkpoint['resources'].items():
        if (len(raw)+4)%512==0:
            raise ValueError('Fresh original resource has unvalidated final512 USB tail: '+name)
        target,_=resources.rename(raw,{1:'Classic Chrome'},LABEL_IDS)
        if (len(target)+4)%512==0:
            raise ValueError('Single-name target has unvalidated final512 USB tail: '+name)
    prior=os.environ.get('A7C2_ZIG_CACHE')
    os.environ['A7C2_ZIG_CACHE']=str(output/'names-zig-cache')
    try:
        targets,build=nameworker.prepare(checkpoint['resources'],{1:'Classic Chrome'},material['original']['AP'],
            uuid.uuid4().hex[:16],output/'names',target_ap=material['candidate']['AP'],label_ids=LABEL_IDS)
    finally:
        if prior is None:os.environ.pop('A7C2_ZIG_CACHE',None)
        else:os.environ['A7C2_ZIG_CACHE']=prior
    specs={}
    for row in build['files']:
        name=row['file'];raw=checkpoint['resources'][name];target=targets[name]
        if resources.inverse(target,row['inverse'])!=raw or sha(raw)!=row['before_sha256'] or sha(target)!=row['after_sha256']:
            raise ValueError('Prepared complete name resource/inverse differs')
        path=output/'payload/resources'/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(target);path.chmod(0o600)
        specs[name]={key:row[key] for key in ('before_bytes','after_bytes','before_sha256','after_sha256')}
        specs[name]['target_file']=_relative(path)
    blob=Path(build['path']).read_bytes()
    worker={'file':_relative(build['path']),'bytes':len(blob),'sha256':sha(blob),'allowed_modes':[0,1,2,3],
            'simulation_passed':False,'mode_meanings':{'0':'check originals only','1':'install and preserve old hardlinks',
            '2':'restore after AP is baseline again','3':'cleanup only after physical acceptance and loaded verification'}}
    return specs,build,worker


def _simulate_sync(manifest,directory):
    from check_single_slot_runtime import validate_artifact
    directory=Path(directory)
    evidence=validate_artifact(directory/'worker.private.json')
    evidence['actual_compiled_worker_executed']=True
    _private_json(directory/'simulation.private.json',evidence)
    result=_read_json(directory/'worker.private.json')
    result['simulation_report']=_relative(directory/'simulation.private.json')
    result['simulation_report_sha256']=sha((directory/'simulation.private.json').read_bytes())
    _private_json(directory/'worker.private.json',result)
    return result


def prepare_recovery_catalog(output):
    """Bounded code variants, never fake fresh live-before observations."""
    from single_slot_runtime import prepare as prepare_sync
    output=Path(output).resolve()
    if output.exists() or (ROOT/'private').resolve() not in output.parents:
        raise ValueError('Use a new private immutable recovery catalog directory')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    catalog={};pairs={(value,0) for value in range(12)}|{(0,value) for value in range(12)}
    for before,target in sorted(pairs):
        folder=output/f'before-{before}-target-{target}'
        worker=prepare_sync(folder,read_only=False,expected_before=before,target=target,require_current_st=True)
        catalog[f'{before}:{target}']=_simulate_sync(worker,folder)
    report={'schema':'a7cr-slot1-recovery-native-catalog/1','workers':catalog,'variant_count':23,
            'camera_accessed':False,'fresh_live_observations':False,'all_require_global_ST':True,
            'simulation_passed':True,'fresh_native_before_required_at_execution':True,
            'to_st':{str(value):f'{value}:0' for value in range(12)},
            'from_st':{str(value):f'0:{value}' for value in range(12)}}
    _private_json(output/'catalog.private.json',report)
    return report


def _read_sync_catalog():
    path=ROOT/'private/single-slot-recovery-native-catalog/catalog.private.json'
    report=_read_json(path)
    expected={f'{value}:0' for value in range(12)}|{f'0:{value}' for value in range(12)}
    if (report.get('schema')!='a7cr-slot1-recovery-native-catalog/1' or report.get('simulation_passed') is not True
            or report.get('fresh_live_observations') is not False or set(report.get('workers',{}))!=expected):
        raise ValueError('Bounded recovery native catalog is incomplete or unverified')
    source_hash=sha((ROOT/'device/native/single_slot_bindings.c').read_bytes())
    for key,worker in report['workers'].items():
        before,target=map(int,key.split(':'))
        if (worker.get('read_only') is not False or worker.get('simulation_passed') is not True
                or worker.get('require_current_st') is not True or worker.get('expected_before')!=before or worker.get('target')!=target
                or worker['worker'].get('source_sha256')!=source_hash):
            raise ValueError('Recovery native catalog worker shape/source differs')
        _validate_existing_worker(worker['worker'])
        simulation_path=ROOT/worker['simulation_report'];simulation=_read_json(simulation_path)
        if (sha(simulation_path.read_bytes())!=worker['simulation_report_sha256'] or simulation.get('passed') is not True
                or simulation.get('actual_compiled_worker_executed') is not True
                or len(simulation.get('cases',[]))!=(8 if before==target else 12)):
            raise ValueError('Recovery catalog actual-worker simulation is missing')
    return {'manifest':_relative(path),'manifest_sha256':sha(path.read_bytes()),
            'recovery_to_st':{str(value):report['workers'][f'{value}:0'] for value in range(12)},
            'recovery_from_st':{str(value):report['workers'][f'0:{value}'] for value in range(12)}}


def _prepare_native_sync(output,native):
    from single_slot_runtime import prepare as prepare_sync
    folder=output/'native-slot-sync'
    worker=prepare_sync(folder,read_only=False,expected_before=native['before_bases'][10],target=0)
    return _simulate_sync(worker,folder)


def _reader_reference(path,*,candidate=False,probe=False):
    path=Path(path);reader=_read_json(path)
    if reader.get('simulation_passed') is not True:
        raise ValueError('Native reader/probe simulation is incomplete')
    _validate_existing_worker(reader['worker'])
    if probe and (reader.get('read_only') is not True or reader.get('selected_slot')!=1):
        raise ValueError('Checkpoint requires the reviewed read-only slot1 native probe')
    if candidate and (reader.get('schema')!='a7cr-slot1-code-reader/1' or len(reader.get('spans',[]))!=16):
        raise ValueError('Candidate reader must cover the reviewed 16 loaded AP spans')
    return {'manifest':_relative(path),'manifest_sha256':sha(path.read_bytes()),'worker':reader['worker']}


def _validate_existing_worker(spec):
    raw=(ROOT/spec['file']).read_bytes()
    if len(raw)!=spec['bytes'] or sha(raw)!=spec['sha256'] or len(raw)>65536:
        raise ValueError('Previously reviewed worker identity differs')
    return dict(spec)


def _wbi_provenance(workers):
    manifest_path=ROOT/'private/native-workers/workers.private.json'
    simulation_path=ROOT/'private/native-workers/simulation.private.json'
    prior=_read_json(manifest_path);simulation=_read_json(simulation_path)
    results={row['case']:row for row in simulation.get('results',[])}
    expected={'wbi-inspect-only':0,'wbi-check-rejects-drop':-22,'wbi-rejects-wrong-start':-22,'wbi-drop-then-mode0':0}
    if prior.get('native_simulation_passed') is not True or simulation.get('schema')!='a7cr-native-syscall-simulation/1':
        raise ValueError('Historical WBI source simulation is not established')
    for name,status in expected.items():
        if name not in results or results[name].get('passed') is not True or results[name].get('status')!=status:
            raise ValueError('Historical WBI boundary case is missing')
    hashes={}
    for name in ('wbi_check','wbi_stage'):
        current=_validate_existing_worker(workers[name]);old=_validate_existing_worker(prior['workers'][name])
        if current['sha256']!=old['sha256'] or current['bytes']!=old['bytes'] or (ROOT/current['file']).read_bytes()!=(ROOT/old['file']).read_bytes():
            raise ValueError('Package WBI worker differs from the previously simulated exact artifact')
        hashes[name]=current['sha256']
    return {'worker_sha256':hashes,'prior_worker_manifest':{'file':_relative(manifest_path),'sha256':sha(manifest_path.read_bytes())},
            'prior_simulation':{'file':_relative(simulation_path),'sha256':sha(simulation_path.read_bytes())},
            'reused_exact_artifacts_without_recompilation':True,'wbi_cases':list(expected),
            'mode2_drop_then_mode0_simulated':True,'camera_current_state_not_inferred':True,
            'limits':'Historical synthetic syscalls and same exact worker blobs; not a new hardware drop or power-loss proof'}


def prepare(checkpoint_path,output):
    """Validate fresh evidence, compile exact workers, keep all readiness false."""
    output=Path(output).resolve()
    private=(ROOT/'private').resolve()
    if output.exists() or private not in output.parents or output in (BASELINE,CANDIDATE) or BASELINE in output.parents or CANDIDATE in output.parents:
        raise ValueError('Use a new private preparation directory outside baseline/candidate')
    material=_load_material();baseline=_load_baseline()
    checkpoint=_read_checkpoint(checkpoint_path,material,baseline)
    if output==checkpoint['path'].parent or checkpoint['path'].parent in output.parents:
        raise ValueError('Prepared output must not alter the read-only checkpoint')
    programs,windows=_normalized_programs(material)
    # Preflight resource tail boundaries before creating any preparation output.
    from looktool import resources
    for name,raw in checkpoint['resources'].items():
        target,_=resources.rename(raw,{1:'Classic Chrome'},LABEL_IDS)
        if (len(raw)+4)%512==0 or (len(target)+4)%512==0:
            raise ValueError('Resource USB final512 tail is not validated: '+name)
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    _private_json(output/'state.private.json',{'phase':'PREPARING_OFFLINE','camera_accessed':False,'ready_for_write':False})
    try:
        workers=_compile_program_workers(output,material,windows)
        named,names_build,workers['names_stage']=_prepare_names(output,checkpoint,material)
        for name in ('wbi_check','wbi_stage'):
            spec=dict(baseline.manifest['files'][name])
            spec['file']=_relative(baseline.root/spec['file'])
            workers[name]=_validate_existing_worker(spec)
        wbi_provenance=_wbi_provenance(workers)
        sync=_prepare_native_sync(output,checkpoint['native'])
        for guard in sync['audit']['guards']:
            at,n=guard['offset'],guard['bytes']
            if material['candidate']['AP'][at:at+n]!=bytes.fromhex(guard['hex']):
                raise ValueError('Candidate changed a guarded original native sync function')
        for kind,raw in material['candidate'].items():
            path=output/'payload'/f'candidate-{kind}.private.bin';path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o600);programs[kind]['candidate_file']=_relative(path)
        original_reader=ROOT/'private/runtime-diagnostic/runtime.private.json'
        candidate_reader=ROOT/'private/single-slot-runtime/candidate-reader/runtime.private.json'
        probe_reader=ROOT/'private/single-slot-runtime/probe-v2/worker.private.json'
        readers={'original':_reader_reference(original_reader),'candidate':_reader_reference(candidate_reader,candidate=True)}
        probe=_reader_reference(probe_reader,probe=True)
        catalog=_read_sync_catalog()
        pending=['Simulate exact program install/inverse native workers including failures',
                 'Simulate exact 68-resource single-name worker modes 0/1/2/3 and failures',
                 'Complete fresh host orchestration/preflight review; no physical or installation authorization is implied']
        manifest={'schema':SCHEMA,'model':'ILCE-7CR','version':'2.01','body_binding':baseline.binding,
            'checkpoint':_relative(checkpoint['path'].parent),'checkpoint_sha256':sha(checkpoint['raw']),
            'copies':checkpoint['checkpoint']['copies'],'files':checkpoint['checkpoint']['files'],
            'checkpoint_raw_evidence':checkpoint['raw_evidence'],'checkpoint_utc':checkpoint['checkpoint'].get('utc'),'same_physical_volume':checkpoint['checkpoint'].get('same_physical_volume'),
            'settings':checkpoint['fields'],'names':{'1':'Classic Chrome'},'selected_mask':1,'selected_slot':1,
            'programs':programs,'resources':named,'workers':workers,'names_build':names_build,'wbi_provenance':wbi_provenance,
            'native_slot_sync':sync,'native_sync_workers':{'install_to_st':sync,**catalog},'native_probe':probe,
            'recovery_native_sync':{'prepared':True,'catalog_compiled_and_stub_simulated':True,'fresh_native_before_required':True,
                'checkpoint_native_slot1_before':checkpoint['native']['before_bases'][10],
                'checkpoint_saved_slot1_before':checkpoint['fields'][0]['before_saved'],
                'requires_current_global_ST':True,'do_not_infer_native_before_from_saved_settings':True},
            'runtime_readers':readers,
            'source_candidate_manifest_sha256':material['manifest_sha256'],'source_ownership_sha256':material['ownership_sha256'],'source_loading_proof_sha256':material['loading_sha256'],
            'offline_program_instruction_tests':material['native_paths'],
            'recovery_order':[{'step':'read fresh native model and prepare both ST sync steps','persistent_write':False},
                {'step':'persist slot1 ST then sync native slot1 to ST','requires_fresh_native_evidence':True},
                {'worker':'ap_stage','mode':2,'program_state_after':'cp_only'},
                {'worker':'cp_stage','mode':2,'program_state_after':'original'},
                {'worker':'names_stage','mode':2,'requires_original_AP':True},
                {'step':'restore only reviewed selected settings and native base with fresh preservation checks'},
                {'worker':'wbi_stage','mode':1,'only_if_required':True},
                {'step':'all IO complete then cold start and readonly verification'}],
            'resource_old_links_cleanup_requires_physical_acceptance':True,
            'no_wholesale_snapshot_restore':True,'camera_accessed':False,'ready_for_write':False,
            'native_worker_simulation_passed':False,'host_flow_tests_passed':False,'device_preflight_passed':False,
            'physical_ready':False,'installation_authorized':False,'installation_prepared':False,'missing_validations':pending}
        _private_json(output/'package.private.json',manifest)
        _private_json(output/'state.private.json',{'phase':'PREPARED_OFFLINE_PENDING_REVIEW','camera_accessed':False,'ready_for_write':False})
        return manifest
    except BaseException as error:
        _private_json(output/'state.private.json',{'phase':'OFFLINE_PREPARATION_FAILED','camera_accessed':False,'ready_for_write':False,
            'error_type':type(error).__name__,'error':str(error)})
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=prepare(args.checkpoint,args.output)
    print(json.dumps({'phase':'PREPARED_OFFLINE_PENDING_REVIEW','output':str(args.output.resolve()),'selected_slot':1,
        'ready_for_write':False,'camera_accessed':False,'missing_validations':result['missing_validations']},indent=2))
