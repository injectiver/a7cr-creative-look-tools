"""New slot-2/3 native synchronization artifacts, based on verified CC source.

Only new files are generated. The installed single-slot artifacts remain
immutable. Sony native functions are independently guarded against the exact
current Classic Chrome AP; writers are slot-specific CAS operations and always
require the owner to select global ST. No USB or device entry point is present.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path.insert(0,str(ROOT/'offline'))
from build_native_workers import compile_worker
import single_slot_runtime as legacy

SOURCE_JOB=ROOT/'private/single-slot-install/classic-chrome'
AP_HASH='585c9bf786600c24926f29432cf263c2e2ee76a8d00975e249c57641dfb56c71'
CP_HASH='8d006427e0279beaad957a5d811e9237b6105afbb8c7c88b6be715bc91e58a82'
AP_PATH=SOURCE_JOB/'payload/candidate-AP.private.bin'
PROC_HASH=legacy.PROC_HASH
FUNCTIONS=dict(legacy.FUNCTIONS)
CURRENT_VA,VALUES_VA,INFO_VA=legacy.CURRENT_VA,legacy.VALUES_VA,legacy.INFO_VA
SLOTS=(2,3)
NATIVE_INDICES={2:11,3:12}
STAGE_NAME='a7cr.portrait-staged.so'
RESULT_NAME='a7cr.portrait.bindings.result'
PROC_RESULT_NAME='a7cr.diag.probe.result'
TEMP_NAMES=frozenset((STAGE_NAME,RESULT_NAME,PROC_RESULT_NAME,'libJit.so'))
OUT=ROOT/'private/portrait-slots-runtime'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def source_evidence():
    # Resolve this project's verified source, never an author's body manifest.
    from single_slot_install import Package
    from portrait_slots_checkpoint import source_evidence as validate_source
    package=Package(SOURCE_JOB,require_write_ready=True)
    proof=validate_source(package)
    return {'source_cc_manifest_sha256':sha((SOURCE_JOB/'package.private.json').read_bytes()),
            'source_verify_file':proof['file'],'source_verify_sha256':proof['sha256'],
            'source_program_sha256':{'AP':AP_HASH,'CP':CP_HASH}}


def audit(raw):
    evidence=source_evidence()
    if sha(raw)!=AP_HASH:raise ValueError('Requires the exact installed Classic Chrome AP')
    baseline=legacy.audit(legacy.AP_PATH.read_bytes())
    for guard in baseline['guards']:
        at,n=guard['offset'],guard['bytes']
        if raw[at:at+n]!=bytes.fromhex(guard['hex']):raise ValueError('CC source changed a native menu function')
    for edge in baseline['calls']:
        if legacy.branch(raw,edge['at'])!=edge['target']:raise ValueError('Source CC native menu edge changed')
    for name,expected in (('current_getter',CURRENT_VA),('values_getter',VALUES_VA),('info_getter',INFO_VA)):
        if legacy.getter(raw,name)!=expected:raise ValueError('Source CC native model pointer changed')
    descriptors={}
    for slot,index in NATIVE_INDICES.items():
        row=struct.unpack_from('<8I',raw,0x57C6710+index*32)
        key=0x02CF0CD0+2*(slot-1)
        if row[:3]!=(3,key,0x10000) or row[6]!=0x14EA+index:
            raise ValueError('Portrait slot base descriptor differs')
        descriptors[str(slot)]={'native_index':index,'key':key,'descriptor_attribute':row[6],
                                'native_menu_attribute':0x14E9+index}
    return {'schema':'a7cr-portrait-native-menu-audit/1',**evidence,'model':'ILCE-7CR','firmware':'2.01',
            'allowed_slots':[2,3],'descriptors':descriptors,'guards':baseline['guards'],
            'calls':baseline['calls'],'model_pointers':baseline['model_pointers'],
            'evidence_type':'exact-current-CC-source-and-static-native-call-graph',
            'camera_executed':False,'hardware_native_calls_verified':False}


def header(report,*,read_only,selected_slot,expected_before,target,require_current_st):
    if type(read_only) is not bool or type(require_current_st) is not bool:raise ValueError('Explicit native mode booleans required')
    if read_only:
        if selected_slot is not None or expected_before is not None or target is not None or require_current_st:
            raise ValueError('Read-only probe contains no selected mutation target')
        index=0
    else:
        if selected_slot not in SLOTS or type(selected_slot) is not int or require_current_st is not True:
            raise ValueError('Writer only supports slot2/3 and requires global ST')
        if any(type(x) is not int or not 0<=x<=11 for x in (expected_before,target)):
            raise ValueError('Writer CAS/target must be bounded native bases')
        index=NATIVE_INDICES[selected_slot]
    lines=[f'#define WRITE_ALLOWED {int(not read_only)}',f'#define SELECTED_SLOT {selected_slot or 0}',
           f'#define SELECTED_INDEX {index}',f'#define EXPECTED_BEFORE {expected_before or 0}',
           f'#define TARGET_BASE {target or 0}','struct Guard {u64 at;u32 size;const u8 *data;};']
    entries=[]
    for i,guard in enumerate(report['guards']):
        lines.append(f'static const u8 guard_{i}[]={{'+','.join(map(str,bytes.fromhex(guard['hex'])))+'};')
        entries.append(f'{{{guard["offset"]}UL,{guard["bytes"]},guard_{i}}}')
    lines+=['static const struct Guard guards[]={'+','.join(entries)+'};',f'static const u32 guard_count={len(entries)};']
    return '\n'.join(lines)+'\n'


def prepare(output,*,read_only=True,selected_slot=None,expected_before=None,target=None,require_current_st=False):
    output=Path(output).resolve()
    if output.exists() or (ROOT/'private').resolve() not in output.parents:
        raise ValueError('Use a new private native artifact directory')
    report=audit(AP_PATH.read_bytes())
    generated=header(report,read_only=read_only,selected_slot=selected_slot,
        expected_before=expected_before,target=target,require_current_st=require_current_st)
    proc=ROOT/'private/runtime-diagnostic/probe.c'
    if sha(proc.read_bytes())!=PROC_HASH:raise ValueError('Reviewed proc reader changed')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    (output/'probe.c').write_bytes(proc.read_bytes())
    source=(ROOT/'device/native/portrait_slots_bindings.c').read_text()
    worker=compile_worker(output,'portrait-probe' if read_only else 'portrait-sync',source,generated)
    result={'schema':'a7cr-portrait-native-worker/1','audit':report,'worker':worker,'read_only':read_only,
            'selected_slot':selected_slot,'selected_native_index':None if read_only else NATIVE_INDICES[selected_slot],
            'expected_before':expected_before,'target':target,'require_current_st':require_current_st,
            'source_sha256':AP_HASH,'proc_reader_sha256':PROC_HASH,'allowed_slots':[2,3],
            'camera_executed':False,'simulation_passed':False,'persistent_settings_may_change':not read_only,
            'firmware_resources_mount_or_wbi_written':False}
    (output/'worker.private.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def decode(raw,*,read_only,selected_slot=None,expected_before=None,target=None,require_current_st=False):
    if type(read_only) is not bool or type(require_current_st) is not bool:raise ValueError('Explicit native mode booleans required')
    if len(raw)!=272:raise ValueError('Incomplete portrait native report')
    magic,version,mode,status,pid,base,current,after_current,changed,reserved=struct.unpack_from('<8sIIqqQIIII',raw)
    if (magic!=b'A7CPR001' or version!=1 or mode!=int(not read_only) or reserved or pid<=0 or base<=0):
        raise ValueError('Wrong portrait native report identity/mode')
    if status:raise ValueError(f'Portrait native report failed: {status}')
    before=list(struct.unpack_from('<18I',raw,56));after=list(struct.unpack_from('<18I',raw,128))
    if raw[264:]!=bytes(8) or current!=after_current or not 0<=current<=17 or any(v>11 for v in before+after):
        raise ValueError('Native values/current/reserved bytes changed unexpectedly')
    wanted=before[:];mask=0
    if read_only:
        if selected_slot is not None or expected_before is not None or target is not None or require_current_st:
            raise ValueError('Read-only decode contains a mutation request')
    else:
        if selected_slot not in SLOTS or type(selected_slot) is not int or require_current_st is not True:
            raise ValueError('Portrait writer requires slot2/3 and global ST')
        if any(type(v) is not int or not 0<=v<=11 for v in (expected_before,target)):
            raise ValueError('Unknown expected/target native base')
        index=NATIVE_INDICES[selected_slot]
        if before[index]!=expected_before or current!=0:raise ValueError('CAS/global ST native evidence failed')
        wanted[index]=target;mask=(1<<index) if target!=before[index] else 0
    if after!=wanted or changed!=mask:raise ValueError('Portrait synchronization changed an unselected base or missed target')
    boot=raw[200:264].split(b'\0',1)[0].decode('ascii')
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n',boot) is None:
        raise ValueError('Native boot identity missing')
    return {'read_only':read_only,'selected_slot':selected_slot,'allowed_slots':[2,3],
            'current':current,'after_current':after_current,'before_bases':before,'after_bases':after,
            'changed_mask':changed,'pid':pid,'base':base,'boot_id':boot,
            'only_selected_portrait_slot_may_change':True}


def prepare_catalog(output):
    output=Path(output).resolve()
    if output.exists():raise ValueError('Use a new immutable portrait catalog directory')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    from check_portrait_slots_runtime import validate_artifact
    workers={};pairs={(v,0) for v in range(12)}|{(0,v) for v in range(12)}
    for slot in SLOTS:
        for before,target in sorted(pairs):
            folder=output/f'slot-{slot}-before-{before}-target-{target}'
            prepare(folder,read_only=False,selected_slot=slot,expected_before=before,target=target,require_current_st=True)
            validate_artifact(folder/'worker.private.json')
            item=json.loads((folder/'worker.private.json').read_text())
            item['simulation_report']=str((folder/'simulation.private.json').relative_to(ROOT))
            item['simulation_report_sha256']=sha((folder/'simulation.private.json').read_bytes())
            (folder/'worker.private.json').write_text(json.dumps(item,indent=2)+'\n')
            workers[f'{slot}:{before}:{target}']=item
    report={'schema':'a7cr-portrait-native-catalog/1','workers':workers,'variant_count':46,'allowed_slots':[2,3],
            'source_sha256':AP_HASH,'camera_accessed':False,'fresh_live_observations':False,
            'all_require_global_ST':True,'fresh_native_before_required_at_execution':True,'simulation_passed':True}
    (output/'catalog.private.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--catalog',action='store_true')
    args=parser.parse_args()
    result=prepare_catalog(args.output) if args.catalog else prepare(args.output)
    print(json.dumps({'camera_accessed':False,'output':str(args.output),'simulation_passed':result['simulation_passed']},indent=2))
