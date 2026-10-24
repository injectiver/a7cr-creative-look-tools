"""Rebuild preset candidates, placement evidence, readers and CAS catalogs.

Private inputs and a locally verified baseline are prerequisites. No USB imports
are executed as camera actions; none of these operations opens a device.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT=runtime_root()
sys.path[:0]=[str(ROOT/'offline'),str(ROOT/'device')]


def _new(paths):
    if any(path.exists() for path in paths):
        raise ValueError('Keep existing asset evidence; inspect the completed/partial build instead of replaying it')


def audit_single(folder,source,target):
    import single_slot_candidate as single
    from audit_lut_storage import ap_incoming,cp_incoming,immediate_references
    for kind in ('AP','CP'):
        if single.sha(source[kind])!=single.EXPECTED[kind]:raise ValueError('Unknown source for placement audit')
    before=struct.unpack_from('<12I',source['CP'],0x20124)
    after=struct.unpack_from('<12I',target['CP'],0x20124)
    if before[:1]+before[2:]!=after[:1]+after[2:]:raise ValueError('Data/BSS descriptors moved')
    from build_lut_candidate import cp_code
    helper,checker=cp_code()
    for address,n in ((single.CP_HELPER,len(helper)),(single.CP_CHECKER,len(checker))):
        if not before[2]<=address<address+n<=before[2]+after[1]<=before[5]:
            raise ValueError('Helper tail is not wholly mapped or overlaps the next segment')
        at=address-single.CP_BASE
        if any(source['CP'][at:at+n]):raise ValueError('Helper source tail has an unreviewed owner')
    report={'schema':'a7cr-single-slot-source-ownership/1','camera_accessed':False,
            'source_program_sha256':{k:single.sha(v) for k,v in source.items()},
            'candidate_program_sha256':{k:single.sha(v) for k,v in target.items()},
            'ap':ap_incoming(source['AP']),'cp_direct_entries':cp_incoming(source['CP']),
            'cp_immediate_reference_review':immediate_references(source['CP']),
            'all_cp_data_and_bss_descriptors_unchanged':True,'helper_tail_loaded_without_next_segment_overlap':True,
            'source_boundary_and_reference_audit_passed':True,'boot_loader_preload_verified_in_this_report':False,
            'physical_boot_verified':False}
    (folder/'source-ownership.private.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def build_single():
    import single_slot_candidate as single
    candidate=ROOT/'private/single-slot-candidate'
    runtime=ROOT/'private/single-slot-runtime'
    catalog=ROOT/'private/single-slot-recovery-native-catalog'
    _new((candidate,runtime,catalog))
    source={k:(single.INPUT/f'candidate-{k}.private.bin').read_bytes() for k in ('AP','CP')}
    comparison={'AP':(single.COMPARISON/'appFw.so').read_bytes(),'CP':(single.COMPARISON/'cpapp-b.bin').read_bytes()}
    table=(ROOT/'private/single-slot-input/fit/slot.raw-s8.private.bin').read_bytes()
    target,manifest=single.build_candidate(source,comparison,table,json.loads(single.ASSETS.read_text()))
    cases=single.verify_native_paths(source,target,manifest)
    manifest['native_instruction_tests_passed']=cases['passed']
    single.write_candidate(candidate,target,manifest)
    (candidate/'native-tests.private.json').write_text(json.dumps(cases,indent=2)+'\n')
    audit_single(candidate,source,target)
    from check_single_slot_loading import check
    check(candidate)
    manifest['placement_audit_passed']=True
    (candidate/'candidate.private.json').write_text(json.dumps(manifest,indent=2)+'\n')
    # Build the first-stage FL23 reader once; it has its own source/target tests.
    initial=ROOT/'private/runtime-diagnostic/runtime.private.json'
    if not initial.exists():
        from build_runtime_diagnostic import build
        from check_runtime_diagnostic import run
        from check_native_workers import Machine
        build();run(Machine,initial,{'original':ROOT/'private/components/ILCE-7CR_2.01/appFw.so',
                                    'candidate':single.INPUT/'candidate-AP.private.bin'})
    else:
        d=json.loads(initial.read_text());blob=(ROOT/d['worker']['file']).read_bytes()
        if not d.get('simulation_passed') or single.sha(blob)!=d['worker']['sha256']:
            raise ValueError('Existing initial code reader is incomplete or changed')
    from single_slot_runtime import prepare
    from prepare_single_slot_installation import _simulate_sync,prepare_recovery_catalog
    probe=runtime/'probe-v2';item=prepare(probe);_simulate_sync(item,probe)
    from build_single_slot_reader import build
    build(runtime/'candidate-reader',candidate)
    prepare_recovery_catalog(catalog)
    return {'stage':'single','candidate':str(candidate),'camera_opened':False,'installable':False}


def build_portrait():
    from portrait_slots_candidate import prepare
    from portrait_slots_runtime import prepare as native_prepare,prepare_catalog
    from check_portrait_slots_runtime import validate_artifact
    from build_portrait_loaded import build
    candidate=ROOT/'private/portrait-candidate';runtime=ROOT/'private/portrait-slots-runtime'
    _new((candidate,runtime))
    prepare(candidate)
    build(runtime/'candidate-reader',candidate)
    probe=runtime/'probe';native_prepare(probe);validate_artifact(probe/'worker.private.json')
    prepare_catalog(runtime/'catalog')
    return {'stage':'portrait','candidate':str(candidate),'camera_opened':False,'installable':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stage',choices=('single','portrait'),required=True)
    args=p.parse_args();print(json.dumps(build_single() if args.stage=='single' else build_portrait(),indent=2))
