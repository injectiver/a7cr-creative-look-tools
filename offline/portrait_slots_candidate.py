"""Offline incremental A7CR CC -> CC/PRO Neg. Std/ASTIA candidate.

Only slots 2 and 3 are added. Current installed CC is reproduced from the
reviewed FL23 source before deriving any new bytes. No USB or device imports.
Existing single-slot sources and packages are read only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import sys as _path_sys
_path_sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.project_paths import runtime_root
ROOT = runtime_root(Path(__file__).resolve().parents[1])
sys.path[:0]=[str(ROOT/'offline'),str(ROOT/'research/repos/a7c2-fl23-research/src/looks')]
import single_slot_candidate as single
from looktool import native,six

CURRENT_PACKAGE=ROOT/'private/single-slot-install/classic-chrome'
CURRENT_SHA={'AP':'585c9bf786600c24926f29432cf263c2e2ee76a8d00975e249c57641dfb56c71',
             'CP':'8d006427e0279beaad957a5d811e9237b6105afbb8c7c88b6be715bc91e58a82'}
NAMES={'1':'Classic Chrome','2':'PRO Neg. Std','3':'ASTIA / SOFT'}
NEW_NAMES={'2':NAMES['2'],'3':NAMES['3']}
INPUTS=ROOT/'private/portrait-inputs'
OUT=ROOT/'private/portrait-candidate'


def sha(raw):return hashlib.sha256(raw).hexdigest()

def private_json(path,value):
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n');path.chmod(0o600)


def load_current():
    manifest=json.loads((CURRENT_PACKAGE/'package.private.json').read_text())
    state=json.loads((CURRENT_PACKAGE/'state.private.json').read_text())
    if (manifest.get('schema')!='a7cr-slot1-offline-installation/1' or manifest.get('selected_mask')!=1
            or manifest.get('names')!={'1':'Classic Chrome'}
            or state.get('phase') not in ('MACHINE_VERIFIED_PENDING_PHOTOS','COMPLETE')):
        raise ValueError('Requires the machine-verified installed single-slot CC baseline')
    programs={kind:(ROOT/manifest['programs'][kind]['candidate_file']).read_bytes() for kind in ('AP','CP')}
    if any(sha(raw)!=CURRENT_SHA[kind] or manifest['programs'][kind]['candidate_sha256']!=CURRENT_SHA[kind]
           for kind,raw in programs.items()):
        raise ValueError('Current CC program identity differs')
    tables=six.read_tables(programs['CP'])
    originals={kind:(single.INPUT/f'candidate-{kind}.private.bin').read_bytes() for kind in ('AP','CP')}
    comparison={'AP':(single.COMPARISON/'appFw.so').read_bytes(),'CP':(single.COMPARISON/'cpapp-b.bin').read_bytes()}
    assets=json.loads(single.ASSETS.read_text())
    regenerated,_=single.build_candidate(originals,comparison,tables[0],assets)
    if regenerated!=programs:raise ValueError('Installed CC baseline cannot be reproduced exactly')
    provenance={'current_package_sha256':sha((CURRENT_PACKAGE/'package.private.json').read_bytes()),
                'current_machine_state_phase':state['phase'],'current_program_sha256':dict(CURRENT_SHA),
                'current_CC_table_sha256':sha(tables[0]),'reproduced_CC_from_reviewed_FL23':True,
                'camera_accessed':False}
    return programs,originals,provenance


def load_fitted_tables():
    result={};reports={}
    expected_profiles={2:'87de86140f7374d17f44cbdd384fbadca1cc99485dc932fcaf2c9125f20fd826',
                       3:'29a82bf333be8b38fce4ada82999c21041414d3e5887bff1c1ac4a1180fd433f'}
    source_files={2:'Sony_ILCE-7CM2_Pro_Neg_Std.dcp',3:'Sony_ILCE-7CM2_Astia.dcp'}
    existing_model=json.loads((ROOT/'private/single-slot-input/fit/candidate.private.json').read_text())['model_sha256']
    for slot in (2,3):
        folder=INPUTS/f'fit-slot{slot}';report=json.loads((folder/'candidate.private.json').read_text())
        raw=(folder/'slot.raw-s8.private.bin').read_bytes();native.decode(raw)
        if (len(raw)!=1215 or sha(raw)!=report['native_table_sha256'] or report['slot']!=slot
                or report['required_base']!='ST' or report['source_inventory']['sha256']!=expected_profiles[slot]
                or sha((INPUTS/source_files[slot]).read_bytes())!=expected_profiles[slot] or report['model_sha256']!=existing_model
                or report['camera_opened'] is not False or report['measured_A7CR_accuracy_verified'] is not False
                or not report['fit']['convergence']['converged']):
            raise ValueError('Portrait DCP source/fit identity differs')
        result[slot]=raw;reports[str(slot)]={'report_file':str((folder/'candidate.private.json').relative_to(ROOT)),
            'report_sha256':sha((folder/'candidate.private.json').read_bytes()),
            'source_profile_sha256':report['source_inventory']['sha256'],'native_table_sha256':sha(raw),
            'model_sha256':report['model_sha256'],'synthetic_fit':report['fit'],
            'measured_A7CR_accuracy_verified':False}
    if reports['2']['model_sha256']!=reports['3']['model_sha256']:
        raise ValueError('Portrait fits use different provisional models')
    return result,reports


def build_candidate(current,tables):
    if set(current)!={'AP','CP'} or any(sha(raw)!=CURRENT_SHA[kind] for kind,raw in current.items()):
        raise ValueError('Exact installed CC AP/CP source is mandatory')
    if set(tables)!={2,3}:raise ValueError('Add exactly portrait slots 2 and 3')
    for raw in tables.values():
        if type(raw) is not bytes or len(raw)!=1215:raise ValueError('Immutable native 1215-byte tables required')
        native.decode(raw)
    from build_lut_candidate import ap_code
    old_code=ap_code(1)[0];new_code=ap_code(7)[0]
    if current['AP'][single.AP_ENTRY:single.AP_END]!=old_code:
        raise ValueError('Installed converter/title mask is not the reviewed CC mask1')
    patch=single.Patches(current)
    changed=[]
    for offset in range(0,len(old_code),4):
        if old_code[offset:offset+4]!=new_code[offset:offset+4]:
            patch.put('AP',single.AP_ENTRY+offset,old_code[offset:offset+4],new_code[offset:offset+4],
                      'Enable slots1/2/3 mask without changing branches or CC slot bit')
            changed.append(single.AP_ENTRY+offset)
    if changed!=[single.AP_ENTRY+24,single.AP_ENTRY+96]:
        raise ValueError('Mask update touches an unreviewed instruction')
    for slot in (2,3):
        at=0x59896f0+(slot-1)*0xb8
        patch.put('AP',at,struct.pack('<I',0x0200a302),struct.pack('<I',0x0200ab2b+slot),
                  f'Only added slot{slot} label reference')
    old_tables=six.read_tables(current['CP']);new_tables=old_tables[:]
    for slot in (2,3):new_tables[slot-1]=tables[slot]
    prefix=six.prefix(new_tables)
    for slot in (2,3):
        checksum=0x8008+(slot-1)*4;at=0x8020+(slot-1)*1215
        patch.put('CP',checksum,current['CP'][checksum:checksum+4],prefix[checksum-0x8000:checksum-0x8000+4],f'Slot{slot} FNV checksum')
        patch.put('CP',at,current['CP'][at:at+1215],tables[slot],f'Only added portrait slot{slot} correction table')
    target=patch.finish()
    if six.read_tables(target['CP'])!=new_tables:raise ValueError('Portrait prefix/table verification failed')
    if target['CP'][0x8008:0x800c]!=current['CP'][0x8008:0x800c] or six.read_tables(target['CP'])[0]!=old_tables[0]:
        raise ValueError('Existing CC table/checksum changed')
    for slot in (1,4,5,6):
        at=0x59896f0+(slot-1)*0xb8
        if target['AP'][at-32:at+36]!=current['AP'][at-32:at+36]:
            raise ValueError('Preserved slot label row changed')
    for slot in (4,5,6):
        if six.read_tables(target['CP'])[slot-1]!=old_tables[slot-1]:raise ValueError('Unselected correction bank changed')
    report={'schema':'a7cr-portrait-slots-candidate/1','model':'ILCE-7CR','version':'2.01',
        'selected_mask':7,'source_selected_mask':1,'added_slots':[2,3],'preserve_slots':[1,4,5,6],
        'names':dict(NAMES),'resource_renames':dict(NEW_NAMES),'required_base':'ST',
        'camera_accessed':False,'installable':False,'device_install_eligible':False,
        'programs':{kind:{'bytes':len(target[kind]),'source_sha256':sha(current[kind]),'candidate_sha256':sha(target[kind]),
                          'windows':patch.windows[kind]} for kind in ('AP','CP')},
        'table_sha256':{str(i+1):sha(raw) for i,raw in enumerate(new_tables)},
        'CC_table_and_checksum_preserved':True,'preserved_slot_label_records':[1,4,5,6],
        'inverse_full_files_exact':True,'native_instruction_tests_passed':False,'placement_audit_passed':False,
        'measured_A7CR_color_accuracy_verified':False,'physical_camera_tested':False}
    return target,report


def verify_native(current,target,report,fl23):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_W0,UC_ARM64_REG_W1,UC_ARM64_REG_X0,UC_ARM64_REG_X2,UC_ARM64_REG_X29,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
    from check_lut_candidate import harness,gamma_tests
    for kind in ('AP','CP'):
        if sha(current[kind])!=report['programs'][kind]['source_sha256'] or sha(target[kind])!=report['programs'][kind]['candidate_sha256']:
            raise ValueError('Portrait native test identity differs')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for at,n in ((single.AP_ENTRY&~4095,0x2000),(single.AP_GETTER&~4095,0x2000),(single.AP_MAP&~4095,4096),(0x30000000,0x3000)):u.mem_map(at,n)
    for at,n in ((single.AP_ENTRY,single.AP_END-single.AP_ENTRY),(single.AP_GETTER-4,40),(single.AP_MAP,12)):
        u.mem_write(at,target['AP'][at:at+n])
    halt,stack,count=0x30002000,0x30001000,0
    for selector in range(18):
        for base in list(range(12))+[255]:
            for reg,value in ((UC_ARM64_REG_W0,selector),(UC_ARM64_REG_W1,base),(UC_ARM64_REG_X2,0x30000000),(UC_ARM64_REG_X30,halt),(UC_ARM64_REG_SP,stack)):
                u.reg_write(reg,value)
            u.mem_write(0x30000000,b'\xa5')
            u.emu_start(single.AP_ENTRY,single.AP_END if base>11 and selector!=16 else halt,count=50)
            expected=255 if selector==16 else selector+239 if base==0 and 10<=selector<=12 else single.NATIVE_MAP[base] if base<=11 else 165
            if (u.mem_read(0x30000000,1)[0]!=expected or u.reg_read(UC_ARM64_REG_PC)!=(single.AP_END if expected==165 else halt)
                    or u.reg_read(UC_ARM64_REG_SP)!=stack):raise ValueError('Portrait mask7 converter mismatch')
            count+=1
    for identity in (0,0x7f7,*range(0x7f8,0x7fe),0x7fe,0xffffffff):
        for reg,value in ((UC_ARM64_REG_X0,0x112233445566),(UC_ARM64_REG_W1,identity),(UC_ARM64_REG_SP,stack),(UC_ARM64_REG_X29,0x12345678),(UC_ARM64_REG_X30,halt)):
            u.reg_write(reg,value)
        selected=0x7f8<=identity<=0x7fa
        u.emu_start(single.AP_GETTER-4,halt if selected else single.AP_GETTER+4,count=40)
        if selected:
            if (u.reg_read(UC_ARM64_REG_W0)!=0x0200ab2c+identity-0x7f8 or u.reg_read(UC_ARM64_REG_SP)!=stack or u.reg_read(UC_ARM64_REG_X29)!=0x12345678):
                raise ValueError('Portrait selected name ABI differs')
        elif (u.reg_read(UC_ARM64_REG_X0)!=0x112233445566 or u.reg_read(UC_ARM64_REG_W1)!=identity
                or u.reg_read(UC_ARM64_REG_SP)!=stack-16 or u.reg_read(UC_ARM64_REG_X29)!=stack-16
                or bytes(u.mem_read(stack-16,16))!=struct.pack('<QQ',0x12345678,halt)):
            raise ValueError('Preserved native name ABI changed')
        count+=1
    env=harness();schedule=env['schedule'];create=env['create'];cp_count=0
    def observed_schedule(image,rows,**options):
        # Compare actual simulated MMIO bytes, not only each image's own
        # hardware_bytes_match boolean (which can be true for two different banks).
        captured=[]
        def capture(*args,**kwargs):
            cpu,counters=create(*args,**kwargs);captured.append(cpu);return cpu,counters
        env['create']=capture
        try:
            states,counters=schedule(image,rows,**options)
            cpu=captured[0]
            actual=b''.join(bytes(cpu.mem_read(mmio+offset,n))
                for mmio in env['MMIOS'] for offset,n in env['CHUNKS'])
            return states,counters,sha(actual)
        finally:env['create']=create
    for marker in (249,250,251):
        for consumer in range(4):
            for root3 in (0,1):
                states,counters=schedule(target['CP'],[(marker,consumer,False),(marker,consumer,True),(marker,consumer,True)],root3=root3)
                if not all(row['hardware_bytes_match'] for row in states[1:]) or counters['builds']!=1:
                    raise ValueError('Portrait cached-preview upload differs')
                cp_count+=1
    native_modes=[(mode,0,True) for mode in (0,1,2,3,5,13,15,16,17,18,19,20,255)]
    for flag in (0,1):
        for direct in (0,1):
            for domain in (0,8,11):
                for root3 in (0,1):
                    options=dict(flag=flag,direct=direct,domain=domain,root3=root3)
                    if observed_schedule(current['CP'],native_modes,**options)!=observed_schedule(target['CP'],native_modes,**options):
                        raise ValueError('Native/FL23 legacy CP behavior changed')
                    if observed_schedule(current['CP'],[(249,0,False),(249,0,True)],**options)!=observed_schedule(target['CP'],[(249,0,False),(249,0,True)],**options):
                        raise ValueError('Existing CC CP behavior changed')
                    cp_count+=2
    for slot in (1,2,3):
        bad=bytearray(target['CP']);bad[0x8008+(slot-1)*4]^=1
        states,_=schedule(bytes(bad),[(249,0,True),(250,0,True),(251,0,True)])
        if states[slot-1]['enabled'] or any(not s['hardware_bytes_match'] for i,s in enumerate(states) if i!=slot-1):
            raise ValueError('Portrait per-table integrity gate failed')
        cp_count+=1
    return {'schema':'a7cr-portrait-native-tests/1','camera_accessed':False,'passed':True,
        'ap_instruction_cases':count,'cp_controller_cases':cp_count,'gamma_cases':gamma_tests(fl23['CP'],target['CP']),
        'CC_native_controller_behavior_preserved':True,'preservation_compares_actual_simulated_MMIO_bytes':True,'limits':'Synthetic CPUs/native controller fixture; no RTOS/ISP/hardware timing or real color acceptance'}


def placement_and_loading(current,target,report):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    from capstone.arm64_const import ARM64_OP_REG,ARM64_OP_IMM
    from audit_lut_bootstrap import replay
    previous=ROOT/'private/single-slot-candidate/source-ownership.private.json'
    prior=json.loads(previous.read_text())
    if not prior['source_boundary_and_reference_audit_passed'] or prior['candidate_program_sha256']!=CURRENT_SHA:
        raise ValueError('Current CC ownership proof differs')
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);decoder.detail=True
    changed_code=[]
    for window in report['programs']['AP']['windows']:
        if single.AP_ENTRY<=window['offset']<single.AP_END:
            a=list(decoder.disasm(bytes.fromhex(window['before_hex']),window['offset']))
            b=list(decoder.disasm(bytes.fromhex(window['after_hex']),window['offset']))
            if len(a)!=1 or len(b)!=1 or a[0].mnemonic!='mov' or b[0].mnemonic!='mov' or a[0].op_str.split(',')[0]!='w3' or b[0].op_str.split(',')[0]!='w3' or a[0].operands[1].imm!=1 or b[0].operands[1].imm!=7:
                raise ValueError('Incremental executable change is not just reviewed mask immediate')
            changed_code.append({'address':window['offset'],'before':a[0].op_str,'after':b[0].op_str})
    if len(changed_code)!=2:raise ValueError('Unexpected portrait executable mask change count')
    cp=bytearray(current['CP'])
    for window in report['programs']['CP']['windows']:
        at,n=window['offset'],window['bytes']
        if not 0x8008<=at<at+n<=0x8000+7322:raise ValueError('CP executable or loader changed during portrait addition')
        cp[at:at+n]=bytes.fromhex(window['after_hex'])
    if bytes(cp)!=target['CP'] or target['CP'][0x20124:0x20154]!=current['CP'][0x20124:0x20154]:
        raise ValueError('CP data/BSS/load descriptors changed')
    ownership={'schema':'a7cr-portrait-source-ownership/1','passed':True,'camera_accessed':False,
        'source_program_sha256':dict(CURRENT_SHA),'candidate_program_sha256':{k:sha(v) for k,v in target.items()},
        'prior_CC_ownership_file':str(previous.relative_to(ROOT)),'prior_CC_ownership_sha256':sha(previous.read_bytes()),
        'executable_changes':changed_code,'no_branch_target_changes':True,'CP_executable_bytes_unchanged':True,
        'CP_data_BSS_descriptors_unchanged':True,'CC_and_unselected_table_banks_preserved':True,
        'evidence_type':'Exact incremental byte scope plus static Capstone and inherited exact-source boundary proof'}
    loaders=[]
    for name in ('loader_spi.bin','mini_ldr.bin','nor-loader_nor.bin'):
        a=(ROOT/'private/components/ILCE-7CR_2.01/lut-references'/name).read_bytes()
        b=(ROOT/'private/components/ILCE-7CM2_2.01/lut-references'/name).read_bytes()
        if a!=b:raise ValueError('Exact loader comparison differs')
        loaders.append({'name':name,'bytes':len(a),'sha256':sha(a)})
    previous_loading=ROOT/'private/single-slot-candidate/loading-proof.private.json'
    old_loading=json.loads(previous_loading.read_text())
    if not old_loading['passed'] or old_loading['candidate_cp_sha256']!=CURRENT_SHA['CP'] or old_loading['exact_common_loaders']!=loaders:
        raise ValueError('Prior exact-source preload proof differs')
    if target['CP'][:0x8000]!=current['CP'][:0x8000]:raise ValueError('Bootstrap/prefix before table bank changed')
    boot=replay(target['CP'])
    if not boot['ok']:raise ValueError('Actual portrait CP bootstrap overwrote table storage')
    loading={'schema':'a7cr-portrait-loading-proof/1','passed':True,'camera_accessed':False,
        'candidate_cp_sha256':sha(target['CP']),'exact_common_loaders':loaders,
        'prior_preload_proof_file':str(previous_loading.relative_to(ROOT)),'prior_preload_proof_sha256':sha(previous_loading.read_bytes()),
        'bootstrap_replay':boot,'table_file_range':[0x8000,0x8000+7322],
        'hardware_MMU_cache_ISP_power_loss_verified':False}
    return ownership,loading


def prepare(output=OUT):
    output=Path(output).resolve()
    if output.exists() or (ROOT/'private') not in output.parents:raise ValueError('Use a new private portrait candidate directory')
    current,fl23,source=load_current();tables,fits=load_fitted_tables()
    target,report=build_candidate(current,tables)
    tests=verify_native(current,target,report,fl23)
    ownership,loading=placement_and_loading(current,target,report)
    report.update(native_instruction_tests_passed=True,placement_audit_passed=True,loading_proof_passed=True)
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    for kind,raw in target.items():
        p=output/f'candidate-{kind}.private.bin';p.write_bytes(raw);p.chmod(0o600)
    inverse={'schema':'a7cr-portrait-exact-inverse/1','camera_accessed':False,'restores':'Existing installed single-slot Classic Chrome',
        'programs':{kind:{'bytes':spec['bytes'],'source_sha256':spec['candidate_sha256'],'candidate_sha256':spec['source_sha256'],
            'windows':[{**w,'before_hex':w['after_hex'],'after_hex':w['before_hex']} for w in spec['windows']]} for kind,spec in report['programs'].items()}}
    provenance={'schema':'a7cr-portrait-source-provenance/1','source':source,'fitted_profiles':fits,
        'original_asset_provenance_file':str((INPUTS/'provenance.private.json').relative_to(ROOT)),
        'original_asset_provenance_sha256':sha((INPUTS/'provenance.private.json').read_bytes()),
        'model_description':'Shared provisional A7C II single-scene inverse-ST/response; not measured A7CR calibration',
        'camera_accessed':False,'physical_color_accuracy_verified':False}
    for name,value in (('native-tests.private.json',tests),('source-ownership.private.json',ownership),
                       ('loading-proof.private.json',loading),('source-provenance.private.json',provenance),('inverse.private.json',inverse)):
        private_json(output/name,value)
    report['evidence']={name:{'file':str((output/name).relative_to(ROOT)),'sha256':sha((output/name).read_bytes())}
        for name in ('native-tests.private.json','source-ownership.private.json','loading-proof.private.json','source-provenance.private.json','inverse.private.json')}
    private_json(output/'candidate.private.json',report)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=OUT)
    result=prepare(parser.parse_args().output)
    print(json.dumps({'selected_mask':7,'added_slots':[2,3],'CC_preserved':True,'programs':{k:v['candidate_sha256'] for k,v in result['programs'].items()},
        'candidate_only':True,'camera_accessed':False,'native_instruction_tests_passed':True,'loading_proof_passed':True},indent=2))
