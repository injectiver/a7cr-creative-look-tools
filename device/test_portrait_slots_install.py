"""Mock-only two-slot sequencing/preservation/failure tests. No USB."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json,tempfile,unittest
from unittest.mock import Mock,patch
import portrait_slots_install as m

OTHER=0x02cf7770
SLOT1=0x02cf0cd0
def item(data,attr=0):return SimpleNamespace(data=data,attr=attr)

def fixture():
    fields=[]
    for slot in m.SLOTS:
        fields.append(dict(slot=slot,key=m.BASE_KEYS[slot],before_ram=bytes([slot+3]).hex(),before_saved=bytes([slot+3]).hex(),after='00'))
        fields.extend(dict(slot=slot,key=key,before_ram=(i+1).to_bytes(4,'little').hex(),before_saved=(i+1).to_bytes(4,'little').hex(),after='00000000') for i,key in enumerate(m.KEYS_BY_SLOT[slot][1:]))
    ap={f['key']:item(bytes.fromhex(f['before_saved'])) for f in fields}
    ap[OTHER]=item(b'later-user-value');ap[SLOT1]=item(b'\0')
    for key in m.COMPANION_KEYS.values():ap[key]=item(bytes(range(13)),0xc0)
    cp={key:item(bytes([i])*8) for i,key in enumerate(m.CP_UNITS)}
    package=SimpleNamespace(root=Path('/not-executed'),fields=fields,binding={'usb_serial_sha256':'synthetic-body'},
        programs={'original':{'AP':b'CC AP'}},manifest={**dict.fromkeys(m.READY_FLAGS,True),'missing_validations':[]},
        readers={},resources={},named_resources={},probe={},sync_workers=[])
    def sync_worker(slot,before,target,*,require_current_st):
        if getattr(package,'missing_restore_worker',False) and slot==3 and target==6:raise m.PreparationBlocked('missing slot3 inverse')
        return dict(selected_slot=slot,expected_before=before,target=target,require_current_st=require_current_st)
    package.sync_worker=sync_worker
    return package,[ap,cp]

class FakeCamera:
    def __init__(self,sections):
        self.state={source:deepcopy(sections) for source in ('memory','flash')}
        self.model=[i%12 for i in range(18)];self.model[10]=0;self.model[11]=5;self.model[12]=6
        self.current=0;self.boot='old-boot';self.image_mode='0\n';self.program_state='original';self.name_state='original';self.loaded_direction='original';self.healthy=True
        self.calls=[];self.selected_allowlist={};self.auto_native=False;self.foreign_after_stage=False
        self.identity={'usb_serial_sha256':'synthetic-body'}
        self.camera=SimpleNamespace(readBackup=lambda key:self.state['memory'][0][key].data)
    def call(self,label,fn,*args):self.calls.append(label);return fn(*args)
    def write_selected(self,key,value):
        if key not in m.SELECTED_KEYS or self.selected_allowlist.get(key)!=value:raise ValueError('outside selected scope')
        self.calls.append(('write',key));self.state['memory'][0][key].data=value
        if self.auto_native and key in m.BASE_KEYS.values():
            slot=next(slot for slot,k in m.BASE_KEYS.items() if key==k);self.model[slot+9]=value[0]
    def save_selected(self):
        self.calls.append('save');self.state['flash']=deepcopy(self.state['memory'])
        if self.foreign_after_stage:self.model[10]=8

def fake_native(camera,worker,folder,record):
    slot=worker['selected_slot'];before=camera.model[:];current=camera.current
    if before[slot+9]!=worker['expected_before'] or current!=0:raise ValueError('native CAS/global ST mismatch')
    camera.model[slot+9]=worker['target']
    for source in camera.state.values():
        key=m.COMPANION_KEYS[slot];array=bytearray(source[0][key].data);array[3]=worker['target'];source[0][key].data=bytes(array)
    record('fake_native_returned',slot=slot)
    return dict(before_bases=before,after_bases=camera.model[:],current=current,after_current=current,pid=77,base=0x50000000,boot_id=camera.boot)

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
        return {'boot_id':camera.boot,'image_mode':camera.image_mode,'pid':77,'base':0x50000000}

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


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.package,sections=fixture();self.camera=FakeCamera(sections);self.job=FlowJob(self.package)
        p=patch.object(m,'invoke_portrait_native',side_effect=fake_native);self.writer=p.start();self.addCleanup(p.stop)
        p=patch.object(m,'slot_fields',return_value=self.package.fields);self.fields=p.start();self.addCleanup(p.stop)
    def installed(self):
        self.job.install(self.camera);self.job.actions.clear();self.camera.boot='cold-boot';self.camera.loaded_direction='candidate'
    def test_both_native_ST_before_cp_then_names_then_ap(self):
        result=self.job.install(self.camera);a=self.job.actions
        self.assertLess(a.index(('probe','install-st-slot3-post-model')),a.index(('native','cp_stage',1)))
        self.assertLess(a.index(('native','cp_stage',1)),a.index(('names',1)))
        self.assertLess(a.index(('names',1)),a.index(('native','ap_stage',1)))
        self.assertEqual(self.camera.model[11:13],[0,0]);self.assertEqual(result['phase'],'INSTALLED_PENDING_COLD_START')
        self.assertEqual(self.writer.call_count,2)
    def test_slot1_and_other_native_slots_and_settings_preserved(self):
        before=self.camera.model[:];self.job.install(self.camera)
        self.assertEqual([v for i,v in enumerate(before) if i not in (11,12)],[v for i,v in enumerate(self.camera.model) if i not in (11,12)])
        self.assertEqual(self.camera.state['flash'][0][SLOT1].data,b'\0');self.assertEqual(self.camera.state['flash'][0][OTHER].data,b'later-user-value')
        self.assertTrue(all(x[1] in m.SELECTED_KEYS for x in self.camera.calls if isinstance(x,tuple)))
    def test_saved_ST_auto_native_uses_prepared_noop_variants(self):
        self.camera.auto_native=True;self.job.install(self.camera)
        self.assertEqual([(c.args[1]['selected_slot'],c.args[1]['expected_before']) for c in self.writer.call_args_list],[(2,0),(3,0)])
    def test_global_ST_required_before_any_write(self):
        self.camera.current=10
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.writer.assert_not_called();self.assertFalse(any(isinstance(x,tuple) for x in self.camera.calls))
    def test_existing_CC_base_required(self):
        self.camera.model[10]=5
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.writer.assert_not_called()
    def test_nonselected_drift_after_save_stops_before_native(self):
        self.camera.foreign_after_stage=True
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.writer.assert_not_called();self.assertNotIn(('native','cp_stage',1),self.job.actions)
    def test_first_native_unknown_result_stops_second_and_programs(self):
        self.writer.side_effect=ValueError('unknown slot2 result')
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertEqual(self.writer.call_count,1);self.assertNotIn(('native','cp_stage',1),self.job.actions)
    def test_second_native_unknown_result_stops_cp(self):
        def invoke(*args):
            if args[1]['selected_slot']==3:raise ValueError('unknown slot3 result')
            return fake_native(*args)
        self.writer.side_effect=invoke
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertEqual(self.writer.call_count,2);self.assertNotIn(('native','cp_stage',1),self.job.actions)
    def test_post_native_probe_drift_stops_next_slot(self):
        def invoke(*args):
            result=fake_native(*args);args[0].model[15]=8;return result
        self.writer.side_effect=invoke
        with self.assertRaisesRegex(ValueError,'post-write model'):self.job.install(self.camera)
        self.assertEqual(self.writer.call_count,1)
    def test_unselected_unsaved_edits_block(self):
        self.camera.state['memory'][0][OTHER].data=b'unsaved'
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.writer.assert_not_called()
    def test_changed_selected_source_blocks(self):
        self.fields.return_value=[]
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.writer.assert_not_called()
    def test_WBI_drop_once_after_program_readbacks(self):
        self.camera.image_mode='2\n';self.job.install(self.camera);a=self.job.actions
        self.assertLess(a.index(('native','wbi_check',0)),a.index(('native','cp_stage',1)))
        self.assertLess(a.index(('programs','after-ap','installed')),a.index(('native','wbi_stage',1)))
        self.assertEqual(a.count(('native','wbi_stage',1)),1)
    def test_ap_failure_never_replays_cp_names_or_invalidates(self):
        self.job.fail_native=('ap_stage',1)
        with self.assertRaises(ValueError):self.job.install(self.camera)
        self.assertEqual(self.job.actions.count(('native','cp_stage',1)),1);self.assertEqual(self.job.actions.count(('names',1)),1)
        self.assertNotIn(('native','wbi_stage',1),self.job.actions)
    def test_restore_order_to_CC_and_both_original_bases(self):
        self.installed();result=self.job.restore(self.camera);a=self.job.actions
        self.assertLess(a.index(('native','ap_stage',2)),a.index(('native','cp_stage',2)))
        self.assertLess(a.index(('native','cp_stage',2)),a.index(('names',2)))
        self.assertEqual(self.camera.model[11:13],[5,6]);self.assertEqual(self.camera.program_state,'original')
        self.assertEqual(result['native_restored_bases'],{'2':5,'3':6})
    def test_restore_before_cold_start_accepts_known_source_loaded(self):
        self.job.install(self.camera);self.job.actions.clear();self.job.restore(self.camera)
        self.assertEqual(self.camera.program_state,'original')
    def test_preflight_both_inverse_setters_before_deactivation(self):
        self.installed();self.package.missing_restore_worker=True;self.camera.calls.clear()
        with self.assertRaises(m.PreparationBlocked):self.job.restore(self.camera)
        self.assertFalse(any(isinstance(x,tuple) for x in self.camera.calls));self.assertNotIn(('native','ap_stage',2),self.job.actions)
    def test_restore_preserves_later_adjustment_and_base(self):
        self.installed();key=m.KEYS_BY_SLOT[2][2]
        for s in self.camera.state.values():s[0][key].data=b'\x08\0\0\0';s[0][m.BASE_KEYS[3]].data=b'\x03'
        self.camera.model[12]=3;result=self.job.restore(self.camera)
        self.assertEqual(self.camera.state['flash'][0][key].data,b'\x08\0\0\0');self.assertEqual(self.camera.model[12],3)
        self.assertIn(f'{key:08x}',result['preserved_later_user_fields'])
    def test_restore_auto_native_coherent_without_second_setter(self):
        self.installed();self.camera.auto_native=True;self.writer.reset_mock();self.job.restore(self.camera)
        self.assertEqual(self.writer.call_count,2)
        self.assertEqual(sum(x['phase']=='native_base_already_coherent_no_writer' for x in self.job.events),2)
    def test_restore_global_ST_before_setting_write(self):
        self.installed();self.camera.current=11;self.camera.calls.clear()
        with self.assertRaises(ValueError):self.job.restore(self.camera)
        self.assertFalse(any(isinstance(x,tuple) for x in self.camera.calls))
    def test_verify_requires_cold_boot_and_both_native_bases(self):
        self.installed();self.job.verify(self.camera,before_boot_id='old-boot');self.camera.model[12]=3
        with self.assertRaises(ValueError):self.job.verify(self.camera,before_boot_id='old-boot')
    def test_verify_preserves_later_microadjustment(self):
        self.installed();key=m.KEYS_BY_SLOT[3][5]
        for s in self.camera.state.values():s[0][key].data=b'\x06\0\0\0'
        self.job.verify(self.camera,before_boot_id='old-boot');self.assertEqual(self.camera.state['flash'][0][key].data,b'\x06\0\0\0')
    def test_initial_loaded_native_identity_must_match_pid_and_base(self):
        for key in ('pid','base'):
            with self.subTest(key=key):
                package,sections=fixture();camera=FakeCamera(sections);job=FlowJob(package)
                original=job.loaded
                def changed(*args,**kwargs):
                    result=original(*args,**kwargs);result[key]+=1;return result
                with patch.object(job,'loaded',side_effect=changed),patch.object(m,'slot_fields',return_value=package.fields):
                    with self.assertRaisesRegex(ValueError,'process changed'):job.install(camera)
                self.assertFalse(any(isinstance(x,tuple) for x in camera.calls))
    def test_verify_and_restore_reject_same_boot_restarted_AP(self):
        self.installed();original=self.job.loaded
        def changed(*args,**kwargs):
            result=original(*args,**kwargs);result['pid']+=1;return result
        with patch.object(self.job,'loaded',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'process changed'):self.job.verify(self.camera,before_boot_id='old-boot')
            self.camera.calls.clear()
            with self.assertRaisesRegex(ValueError,'process changed'):self.job.restore(self.camera)
            self.assertFalse(any(isinstance(x,tuple) for x in self.camera.calls))
    def test_companion_scope_never_allows_slot1_change(self):
        _,s=fixture();after=deepcopy(s);after[0][SLOT1].data=b'\x05'
        with self.assertRaises(ValueError):m.selected_preservation(s,after,{m.BASE_KEYS[2]:b'\x05'},native_targets={2:5})


class EntryTests(unittest.TestCase):
    def receipts(self,root,*,wrong_worker=False):
        workspace=root/'private/job';workspace.mkdir(parents=True)
        (root/'device').mkdir()
        sources={}
        for name in ('portrait_slots_install.py','test_portrait_slots_install.py'):
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
        reports['names'].update(resource_count=68,selected_mask=6,actual_full_resource_cases=[{'case':case,'passed':True} for case in
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
                (root/'device/portrait_slots_install.py').write_bytes(b'changed after test')
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
            (folder/'events.private.json').write_text(json.dumps([{'phase':'portrait_slots_command_started'}]))
            with self.assertRaises(m.PreparationBlocked):m.guard_existing_write_attempts(root)

    def test_only_complete_normal_usb_write_receipt_closes_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);folder=root/'restore-complete';folder.mkdir()
            (folder/'events.private.json').write_text(json.dumps([{'phase':'portrait_slots_command_complete','normal_usb_return_confirmed':True}]))
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
                 patch.object(m,'invoke_portrait_native',side_effect=fake_native):
                with self.assertRaises(ValueError):m.run(package.root,'install',battery_percent=90,session_factory=session)
            self.assertEqual(session.call_count,1)
            self.assertEqual(json.loads((package.root/'state.private.json').read_text())['phase'],'STOPPED_INSPECTION_REQUIRED')
            self.assertEqual(job_holder[0].actions.count(('native','cp_stage',1)),1)


if __name__=='__main__':unittest.main()
