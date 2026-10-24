"""Mock-only host sequencing, preservation and no-replay tests. No USB."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

import single_slot_install as m


OTHER=0x02CF0999


def item(data,attr=0):return SimpleNamespace(data=data,attr=attr)


def fixture():
    fields=[dict(slot=1,key=m.BASE_KEY,before_ram='05',before_saved='05',after='00')]
    fields += [dict(slot=1,key=key,before_ram=(i+1).to_bytes(4,'little').hex(),
                   before_saved=(i+1).to_bytes(4,'little').hex(),after='00000000')
               for i,key in enumerate(m.SLOT_KEYS[1:])]
    ap={f['key']:item(bytes.fromhex(f['before_saved'])) for f in fields}
    ap[OTHER]=item(b'newer-user-value')
    ap[m.COMPANION_KEY]=item(bytes(range(13)),0xc0)
    ap[0x02CF1287]=item(b'\x0a');ap[0x02CF1289]=item(b'\x0b')
    cp={key:item(bytes([i])*8) for i,key in enumerate(m.CP_UNITS)}
    sections=[ap,cp]
    fl23=SimpleNamespace(units={'candidate':{k:v.data for k,v in cp.items() if k in (0x02A40001,0x02A4000D)}},
        protected={k:v.data for k,v in cp.items() if k not in (0x02A40001,0x02A4000D)},
        bindings={'candidate':{0x02CF1287:b'\x0a',0x02CF1289:b'\x0b'}})
    package=SimpleNamespace(root=Path('/not-executed'),fields=fields,fl23=fl23,
        binding={'usb_serial_sha256':'synthetic-camera'},programs={'original':{'AP':b'baseline AP'}},
        manifest={**dict.fromkeys(m.READY_FLAGS,True),'missing_validations':[]},
        readers={},resources={},named_resources={},probe={},sync_workers=[])
    def sync_worker(before,target,*,require_current_st):
        if getattr(package,'missing_restore_worker',False) and target==5:
            raise m.PreparationBlocked('missing original-base worker')
        return dict(expected_before=before,target=target,require_current_st=require_current_st)
    package.sync_worker=sync_worker
    return package,sections


class FakeCamera:
    def __init__(self,sections):
        self.state={source:deepcopy(sections) for source in ('memory','flash')}
        self.model=[i%12 for i in range(18)];self.model[10]=5
        self.current=0;self.boot='old-boot';self.image_mode='0\n'
        self.program_state='original';self.name_state='original';self.healthy=True
        self.loaded_direction='original'
        self.identity={'usb_serial_sha256':'synthetic-camera'}
        self.calls=[];self.selected_allowlist={}
        self.auto_native=False;self.foreign_after_stage=False
        self.camera=SimpleNamespace(readBackup=lambda key:self.state['memory'][0][key].data)

    def call(self,label,fn,*args):
        self.calls.append(label);return fn(*args)

    def write_selected(self,key,value):
        if self.selected_allowlist.get(key)!=value:raise ValueError('unallowlisted fake write')
        self.calls.append(('write',key,value));self.state['memory'][0][key].data=value
        if key==m.BASE_KEY and self.auto_native:
            self.model[10]=value[0]
            array=bytearray(self.state['memory'][0][m.COMPANION_KEY].data);array[5]=value[0]
            self.state['memory'][0][m.COMPANION_KEY].data=bytes(array)
        if key==m.BASE_KEY and self.foreign_after_stage:self.model[11]=8

    def save_selected(self):
        self.calls.append('save');self.state['flash']=deepcopy(self.state['memory'])


class FlowJob(m.Job):
    def __init__(self,package,attempt=Path('/not-executed')):
        super().__init__(package,attempt);self.actions=[];self.fail_native=None

    def record(self,phase,**detail):
        self.events.append({'phase':phase,**detail})
        if self.attempt.is_dir():m.durable_json(self.attempt/'events.private.json',self.events)

    def phase(self,phase,**detail):
        self.actions.append(('phase',phase));self.last_phase=phase
        if self.package.root.is_dir():m.durable_json(self.package.root/'state.private.json',{'phase':phase,**detail})

    def folder(self,tag):return self.attempt/tag

    def snapshots(self,camera,tag):
        self.actions.append(('snapshot',tag));return deepcopy(camera.state)

    def program_state(self,camera,tag,expected=None):
        self.actions.append(('programs',tag,camera.program_state))
        if expected is not None and expected!=camera.program_state:raise ValueError('unknown full program state')
        if camera.program_state not in ('original','cp_only','installed'):raise ValueError('unknown full program state')
        return camera.program_state

    def titles(self,camera,*,named=None):
        self.actions.append(('titles',named))
        if camera.name_state not in ('original','named'):raise ValueError('unknown resources')
        if named is not None and camera.name_state!=('named' if named else 'original'):raise ValueError('wrong resources')
        return camera.name_state

    def loaded(self,camera,tag,direction,*,allow_known_loaded=False):
        self.actions.append(('loaded',direction))
        if not allow_known_loaded and camera.loaded_direction!=direction:raise ValueError('wrong loaded AP')
        return {'boot_id':camera.boot,'image_mode':camera.image_mode}

    def probe(self,camera,tag):
        self.actions.append(('probe',tag))
        return {'before_bases':camera.model[:],'after_bases':camera.model[:], 'current':camera.current,
            'after_current':camera.current,'pid':77,'base':0x50000000,'boot_id':camera.boot}

    def native(self,camera,kind,mode):
        self.actions.append(('native',kind,mode))
        if self.fail_native==(kind,mode):raise ValueError('simulated unresolved native write')
        transitions={('cp_stage',1):'cp_only',('ap_stage',1):'installed',
                     ('ap_stage',2):'cp_only',('cp_stage',2):'original'}
        if (kind,mode) in transitions:camera.program_state=transitions[kind,mode]
        if kind=='wbi_stage':camera.image_mode='0\n'

    def names_native(self,camera,mode):
        self.actions.append(('names',mode))
        if mode in (1,2):camera.name_state='named' if mode==1 else 'original'


def fake_writer(camera,worker,folder,record):
    before=camera.model[:];current=camera.current
    if before[10]!=worker['expected_before'] or (worker['require_current_st'] and current!=0):
        camera.healthy=False;raise ValueError('native CAS/global ST mismatch')
    camera.model[10]=worker['target']
    for source in camera.state.values():
        array=bytearray(source[0][m.COMPANION_KEY].data);array[3]=worker['target']
        source[0][m.COMPANION_KEY].data=bytes(array)
    record('fake_native_sync_returned')
    return {'before_bases':before,'after_bases':camera.model[:],'current':current,'after_current':current,
            'pid':77,'base':0x50000000,'boot_id':camera.boot}


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.package,sections=fixture();self.camera=FakeCamera(sections);self.job=FlowJob(self.package)
        self.ctx=patch.object(m,'invoke_slot_writer',side_effect=fake_writer);self.ctx.start();self.addCleanup(self.ctx.stop)
        fields=patch.object(m,'slot_fields',return_value=self.package.fields);self.fields=fields.start();self.addCleanup(fields.stop)

    def installed(self):
        self.job.install(self.camera);self.job.actions.clear();self.camera.boot='cold-boot';self.camera.loaded_direction='candidate'

    def test_install_saved_st_and_native_model_before_any_program_write(self):
        result=self.job.install(self.camera)
        actions=self.job.actions
        staged=next(i for i,a in enumerate(actions) if a==('snapshot','sync-st-before-programs-after'))
        cp=actions.index(('native','cp_stage',1));names=actions.index(('names',1));ap=actions.index(('native','ap_stage',1))
        self.assertLess(staged,cp);self.assertLess(cp,names);self.assertLess(names,ap)
        self.assertEqual(self.camera.model[10],0);self.assertEqual(result['phase'],'INSTALLED_PENDING_COLD_START')
        self.assertNotIn(('native','wbi_stage',1),actions)

    def test_mode2_has_preflight_and_one_wbi_drop_after_programs(self):
        self.camera.image_mode='2\n';self.job.install(self.camera)
        actions=self.job.actions
        self.assertLess(actions.index(('native','wbi_check',0)),actions.index(('native','cp_stage',1)))
        self.assertLess(actions.index(('native','ap_stage',1)),actions.index(('native','wbi_stage',1)))
        self.assertEqual(actions.count(('native','wbi_stage',1)),1)

    def test_install_owner_global_st_required_before_any_setting_write(self):
        self.camera.current=10
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertFalse(any(isinstance(call,tuple) for call in self.camera.calls))
        self.assertNotIn(('native','cp_stage',1),self.job.actions)

    def test_saved_st_may_already_sync_native_model_and_uses_prepared_noop(self):
        self.camera.auto_native=True
        self.job.install(self.camera)
        worker=m.invoke_slot_writer.call_args[0][1]
        self.assertEqual((worker['expected_before'],worker['target']),(0,0))
        self.assertTrue(worker['require_current_st'])
        self.assertEqual(self.camera.model[10],0)

    def test_foreign_model_drift_after_saved_st_blocks_program_writes(self):
        self.camera.foreign_after_stage=True
        with self.assertRaises(ValueError):self.job.install(self.camera)
        m.invoke_slot_writer.assert_not_called()
        self.assertNotIn(('native','cp_stage',1),self.job.actions)

    def test_other_slot_and_unrelated_settings_preserved(self):
        self.camera.state['memory'][0][0x02CF0CD2]=item(b'\x09')
        self.camera.state['flash'][0][0x02CF0CD2]=item(b'\x09')
        self.job.install(self.camera)
        self.assertEqual(self.camera.state['flash'][0][0x02CF0CD2].data,b'\x09')
        self.assertEqual(self.camera.state['flash'][0][OTHER].data,b'newer-user-value')
        self.assertTrue(all(call[1] in m.SLOT_KEYS for call in self.camera.calls if isinstance(call,tuple)))

    def test_unselected_unsaved_value_blocks_before_persistent_write(self):
        self.camera.state['memory'][0][OTHER].data=b'unsaved'
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertFalse(any(isinstance(call,tuple) for call in self.camera.calls))
        self.assertNotIn(('native','cp_stage',1),self.job.actions)

    def test_selected_saved_source_drift_blocks_before_program_write(self):
        self.fields.return_value=[{**f,'before_saved':'99'} if i==0 else f for i,f in enumerate(self.package.fields)]
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertNotIn(('native','cp_stage',1),self.job.actions)

    def test_native_sync_failure_does_not_reach_cp_stage_or_retry(self):
        m.invoke_slot_writer.side_effect=ValueError('native result unknown')
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertEqual(m.invoke_slot_writer.call_count,1)
        self.assertNotIn(('native','cp_stage',1),self.job.actions)

    def test_ap_failure_after_cp_does_not_repeat_cp_or_names(self):
        self.job.fail_native=('ap_stage',1)
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertEqual(self.job.actions.count(('native','cp_stage',1)),1)
        self.assertEqual(self.job.actions.count(('names',1)),1)
        self.assertNotIn(('native','wbi_stage',1),self.job.actions)

    def test_restore_current_selection_requires_owner_global_st_before_write(self):
        self.installed();self.camera.current=10;self.camera.calls.clear()
        with self.assertRaises(ValueError):self.job.restore(self.camera)
        self.assertFalse(any(isinstance(call,tuple) for call in self.camera.calls))
        self.assertFalse(any(a[0]=='native' for a in self.job.actions))

    def test_restore_preflights_inverse_native_writer_before_deactivation(self):
        self.installed();self.package.missing_restore_worker=True;self.camera.calls.clear()
        with self.assertRaises(m.PreparationBlocked):self.job.restore(self.camera)
        self.assertFalse(any(isinstance(call,tuple) for call in self.camera.calls))
        self.assertNotIn(('native','ap_stage',2),self.job.actions)

    def test_restore_ap_before_cp_then_names_original_base(self):
        self.installed();result=self.job.restore(self.camera);actions=self.job.actions
        self.assertLess(actions.index(('native','ap_stage',2)),actions.index(('native','cp_stage',2)))
        self.assertLess(actions.index(('native','cp_stage',2)),actions.index(('names',2)))
        self.assertEqual(self.camera.model[10],5)
        self.assertEqual(self.camera.state['flash'][0][m.BASE_KEY].data,b'\x05')
        self.assertEqual(result['phase'],'RESTORED_PENDING_COLD_START')
        self.assertFalse(result['physical_recovery_verified'])

    def test_known_baseline_loaded_before_cold_start_can_restore(self):
        self.job.install(self.camera);self.job.actions.clear()
        self.assertEqual(self.camera.loaded_direction,'original')
        result=self.job.restore(self.camera)
        self.assertEqual(result['phase'],'RESTORED_PENDING_COLD_START')
        self.assertEqual(self.camera.program_state,'original')

    def test_restore_preserves_later_user_adjustment_and_native_base(self):
        self.installed();key=m.SLOT_KEYS[2]
        for sections in self.camera.state.values():
            sections[0][key].data=b'\x08\0\0\0';sections[0][m.BASE_KEY].data=b'\x03'
        self.camera.model[10]=3
        result=self.job.restore(self.camera)
        self.assertEqual(self.camera.state['flash'][0][key].data,b'\x08\0\0\0')
        self.assertEqual(self.camera.model[10],3)
        self.assertIn(f'{key:08x}',result['preserved_later_user_fields'])
        self.assertEqual(self.camera.state['flash'][0][OTHER].data,b'newer-user-value')

    def test_restore_saved_original_base_may_already_sync_without_second_writer(self):
        self.installed();self.camera.auto_native=True;m.invoke_slot_writer.reset_mock()
        self.job.restore(self.camera)
        self.assertEqual(m.invoke_slot_writer.call_count,1)
        self.assertEqual(self.camera.model[10],5)
        self.assertTrue(any(e['phase']=='native_base_already_coherent_no_writer' for e in self.job.events))

    def test_restore_preserves_unsaved_selected_user_edits_by_stopping(self):
        self.installed();self.camera.calls.clear()
        self.camera.state['memory'][0][m.SLOT_KEYS[2]].data=b'\x09\0\0\0'
        with self.assertRaises(ValueError):self.job.restore(self.camera)
        self.assertFalse(any(isinstance(call,tuple) for call in self.camera.calls))

    def test_unknown_resource_or_program_never_gets_recovery_writes(self):
        self.installed();self.camera.program_state='unknown'
        with self.assertRaises(ValueError):self.job.restore(self.camera)
        self.assertFalse(any(a[0]=='native' for a in self.job.actions))

    def test_verify_is_readonly_and_needs_new_boot(self):
        self.installed()
        result=self.job.verify(self.camera,before_boot_id='old-boot')
        self.assertEqual(result['phase'],'MACHINE_VERIFIED_PENDING_PHOTOS')
        self.assertEqual(result['before_boot_id'],'old-boot')
        self.assertFalse(any(a[0] in ('native','names') for a in self.job.actions))
        with self.assertRaises(ValueError):self.job.verify(self.camera,before_boot_id='cold-boot')

    def test_verify_does_not_reset_intentional_adjustments(self):
        self.installed();key=m.SLOT_KEYS[3]
        for sections in self.camera.state.values():sections[0][key].data=b'\x07\0\0\0'
        self.job.verify(self.camera,before_boot_id='old-boot',physical_accepted=True)
        self.assertEqual(self.camera.state['flash'][0][key].data,b'\x07\0\0\0')
        self.assertFalse(any(a[0] in ('native','names') for a in self.job.actions))

    def test_verify_rejects_saved_st_but_native_bw(self):
        self.installed();self.camera.model[10]=8
        with self.assertRaises(ValueError):self.job.verify(self.camera,before_boot_id='old-boot')

    def test_restored_verify_requires_actual_native_base_agreement(self):
        self.installed();self.job.restore(self.camera);self.camera.boot='restored-cold-boot';self.camera.loaded_direction='original'
        result=self.job.verify(self.camera,restored=True,before_boot_id='cold-boot')
        self.assertEqual(result['phase'],'RESTORED_MACHINE_VERIFIED_PENDING_PHOTOS')
        self.camera.model[10]=8
        with self.assertRaises(ValueError):self.job.verify(self.camera,restored=True,before_boot_id='cold-boot')


class PreservationTests(unittest.TestCase):
    def test_recovery_loaded_spans_must_collectively_match_known_full_direction(self):
        package,_=fixture();source=b'abcdefghijklmnop';target=b'AbcdefghIjklmnop'
        package.programs={'original':{'AP':source},'candidate':{'AP':target}}
        spans=[{'offset':i,'bytes':1} for i in range(16)]
        package.readers={'candidate':{'spans':spans,'worker':{}}}
        job=FlowJob(package)
        def result(live):return {'ok':True,'spans':[{'loaded_hex':live[i:i+1].hex(),'disk_hex':target[i:i+1].hex()} for i in range(16)]}
        with patch.object(m,'_blob',return_value=b'compiled-reader'),patch.object(m,'loaded_invoke',return_value=result(source)):
            out=m.Job.loaded(job,None,'test','candidate',allow_known_loaded=True)
            self.assertEqual(out['accepted_loaded_state'],['original'])
        mixed=bytearray(source);mixed[0]=target[0]
        with patch.object(m,'_blob',return_value=b'compiled-reader'),patch.object(m,'loaded_invoke',return_value=result(bytes(mixed))),self.assertRaisesRegex(ValueError,'mixed'):
            m.Job.loaded(job,None,'test','candidate',allow_known_loaded=True)

    def test_native_array_change_only_to_target_is_allowed(self):
        _,before=fixture();after=deepcopy(before)
        raw=bytearray(after[0][m.COMPANION_KEY].data);raw[5]=0;after[0][m.COMPANION_KEY].data=bytes(raw)
        m.selected_preservation(before,after,{},native_target=0)
        with self.assertRaises(ValueError):m.selected_preservation(before,after,{})
        raw[4]=9;after[0][m.COMPANION_KEY].data=bytes(raw)
        with self.assertRaises(ValueError):m.selected_preservation(before,after,{},native_target=0)

    def test_native_scope_never_allows_other_setting_or_calibration(self):
        _,before=fixture();after=deepcopy(before);after[0][OTHER].data=b'changed'
        with self.assertRaises(ValueError):m.selected_preservation(before,after,{},native_target=0)
        after=deepcopy(before);after[1][0x02A40002].data=b'changed'
        with self.assertRaises(ValueError):m.selected_preservation(before,after,{},native_target=0)


class EntryTests(unittest.TestCase):
    def receipts(self,root,*,wrong_worker=False):
        workspace=root/'private/job';workspace.mkdir(parents=True)
        (root/'device').mkdir()
        sources={}
        for name in ('single_slot_install.py','test_single_slot_install.py'):
            path=root/'device'/name;path.write_bytes(b'synthetic test source')
            sources['device/'+name]=m.sha(path.read_bytes())
        workers={name:{'sha256':m.sha(name.encode())} for name in ('program_check','installed_check','cp_stage','ap_stage','names_stage')}
        reports={'native_programs':{'passed':True,'worker_sha256':{name:spec['sha256'] for name,spec in workers.items() if name!='names_stage'}},
                 'names':{'passed':True,'worker_sha256':{'names_stage':workers['names_stage']['sha256']}},
                 'host_flow':{'passed':True,'tests_run':1,'sources_sha256':sources}}
        reports['native_programs']['actual_full_size_worker_cases']=[{'case':case,'passed':True} for case in
            ('baseline-check','cp-install','ap-install','installed-check','restore-ap-first','restore-cp-second',
             'cp-short-write-rolls-back','ap-short-write-rolls-back','wrong-full-source-digest')]
        reports['native_programs']['native_hash_algorithm_reduced_fixture_cases']=[{'passed':True}]
        reports['names'].update(resource_count=68,selected_mask=1,actual_full_resource_cases=[{'case':case,'passed':True} for case in
            ('names-readonly-all68','names-install-all68','names-inverse-all68','names-inverse-reconstruct-after-cleanup',
             'names-stage-write-rollback','names-link-failure-rollback','names-second-commit-rollback')])
        if wrong_worker:reports['native_programs']['worker_sha256']['cp_stage']=m.sha(b'different worker')
        refs={}
        for kind,report in reports.items():
            path=workspace/(kind+'.json');path.write_text(json.dumps(report))
            refs[kind]={'file':str(path.relative_to(root)),'sha256':m.sha(path.read_bytes())}
        return workspace,{'workers':workers,'validation_receipts':refs}

    def test_validation_receipts_bind_actual_worker_and_current_host_source(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);workspace,manifest=self.receipts(root)
            with patch.object(m,'ROOT',root),patch('tools.project_paths.source_root',return_value=root):
                m.validate_receipts(manifest,workspace)
                (root/'device/single_slot_install.py').write_bytes(b'changed after test')
                with self.assertRaisesRegex(m.PreparationBlocked,'host source changed'):
                    m.validate_receipts(manifest,workspace)

    def test_ready_flags_do_not_accept_another_workers_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);workspace,manifest=self.receipts(root,wrong_worker=True)
            with patch.object(m,'ROOT',root),self.assertRaisesRegex(m.PreparationBlocked,'different workers'):
                m.validate_receipts(manifest,workspace)

    def test_no_ready_flag_can_be_inferred_from_cpu_checks(self):
        for key in m.READY_FLAGS:
            manifest={**dict.fromkeys(m.READY_FLAGS,True),'missing_validations':[]};manifest[key]=False
            with self.subTest(key=key),self.assertRaises(m.PreparationBlocked):m.require_ready(manifest)

    def test_unknown_attempt_phase_cannot_install_or_restore(self):
        for command in ('install','restore'):
            with self.subTest(command=command),self.assertRaises(m.PreparationBlocked):
                m.validate_command_state(command,{'phase':'STOPPED_INSPECTION_REQUIRED'})

    def test_low_battery_is_rejected_before_package_or_session(self):
        factory=Mock()
        with patch.object(m,'Package') as package:
            with self.assertRaises(m.PreparationBlocked):m.run(Path('/not-used'),'install',battery_percent=74,session_factory=factory)
            package.assert_not_called();factory.assert_not_called()

    def test_crashed_write_attempt_blocks_even_if_state_still_prepared(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);folder=root/'install-abrupt';folder.mkdir()
            (folder/'events.private.json').write_text(json.dumps([{'phase':'single_slot_command_started'}]))
            with self.assertRaises(m.PreparationBlocked):m.guard_existing_write_attempts(root)

    def test_only_complete_normal_usb_write_receipt_closes_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);folder=root/'restore-complete';folder.mkdir()
            (folder/'events.private.json').write_text(json.dumps([{'phase':'single_slot_command_complete','normal_usb_return_confirmed':True}]))
            m.guard_existing_write_attempts(root)

    def test_run_records_unknown_install_failure_and_never_reopens_session(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'private').mkdir();package,sections=fixture();package.root=root/'job';package.root.mkdir()
            (package.root/'state.private.json').write_text(json.dumps({'phase':'PREPARED_NOT_INSTALLED'}))
            camera=FakeCamera(sections);job_holder=[]
            def job_factory(p,a):
                job=FlowJob(p,a);job.fail_native=('ap_stage',1);job_holder.append(job);return job
            session=Mock();session.return_value.__enter__=Mock(return_value=camera);session.return_value.__exit__=Mock(return_value=False)
            with patch.object(m,'ROOT',root),patch.object(m,'Package',return_value=package),patch.object(m,'Job',side_effect=job_factory),\
                 patch.object(m.os,'geteuid',return_value=0),patch.object(m,'slot_fields',return_value=package.fields),\
                 patch.object(m,'invoke_slot_writer',side_effect=fake_writer):
                with self.assertRaises(ValueError):m.run(package.root,'install',battery_percent=90,session_factory=session)
            self.assertEqual(session.call_count,1)
            self.assertEqual(json.loads((package.root/'state.private.json').read_text())['phase'],'STOPPED_INSPECTION_REQUIRED')
            self.assertEqual(job_holder[0].actions.count(('native','cp_stage',1)),1)


if __name__=='__main__':unittest.main()
