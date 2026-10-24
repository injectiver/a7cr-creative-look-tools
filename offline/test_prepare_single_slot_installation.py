"""Synthetic offline checkpoint/package validation; never camera evidence."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_single_slot_installation as mod


class PrepareTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='a7cr-slot1-synthetic-prep-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();(self.root/'private').mkdir()
        self.root_patch=patch.object(mod,'ROOT',self.root);self.root_patch.start();self.addCleanup(self.root_patch.stop)
        self.folder=self.root/'private/checkpoint';self.folder.mkdir()
        self.output=self.root/'private/prepared'
        self.original={'AP':b'A'*128,'CP':b'C'*128};self.target={'AP':b'A'*8+b'look'+b'A'*116,'CP':b'C'*32+b'colour'+b'C'*90}
        windows={'AP':[{'offset':8,'bytes':4,'before_hex':b'AAAA'.hex(),'after_hex':b'look'.hex(),'purpose':'single slot'}],
                 'CP':[{'offset':32,'bytes':6,'before_hex':b'CCCCCC'.hex(),'after_hex':b'colour'.hex(),'purpose':'single slot table'}]}
        self.material={'original':self.original,'candidate':self.target,'manifest':{'programs':{
            k:{'source_sha256':mod.sha(self.original[k]),'candidate_sha256':mod.sha(self.target[k]),'bytes':128,'windows':windows[k]} for k in ('AP','CP')}},
            'manifest_sha256':'1'*64,'ownership_sha256':'2'*64,'loading_sha256':'3'*64,'native_paths':{'passed':True,'camera_accessed':False}}
        serial=b'\x01\x02\x03\x04'
        binding={'model':'ILCE-7CR','usb_serial_sha256':'4'*64,'ap_serial_sha256':mod.sha(serial.hex().encode())}
        units={key:bytes([index+1])*n for index,(key,n) in enumerate(mod.CP_UNITS.items())}
        self.baseline=SimpleNamespace(binding=binding,units={'candidate':units},protected={},root=self.root,manifest={'files':{}})
        self.compiled=[]
        self.patch(patch.object(mod,'_load_material',return_value=self.material))
        self.patch(patch.object(mod,'_load_baseline',return_value=self.baseline))
        for worker in ('wbi_check','wbi_stage'):
            self.baseline.manifest['files'][worker]=self.fake_worker(self.root/'private/old-workers'/worker,worker,'wbi')
        props={key:SimpleNamespace(data=(b'\0' if key==0x02cf0cd0 else bytes(4)),attr=0) for key in mod.SELECTED_KEYS}
        props[0x00e70003]=SimpleNamespace(data=serial,attr=0)
        props[0x02cf7770]=SimpleNamespace(data=b'unselected',attr=0)
        snapshot=[props,{key:SimpleNamespace(data=value,attr=0) for key,value in units.items()}]
        self.snapshots={f'{tag}-{kind}.bin':deepcopy(snapshot) for tag in ('before','after') for kind in ('memory','flash')}
        self.patch(patch.object(mod,'_decode_snapshot',side_effect=lambda raw:deepcopy(self.snapshots[raw.decode()])))
        self.patch(patch.object(mod,'_derive_fields',side_effect=self.derive_fields))
        self.raw_evidence_patch=patch.object(mod,'_decode_live_evidence',return_value={'binary_reports_redecoded':True,'files':{}})
        self.patch(self.raw_evidence_patch)
        self.patch(patch('build_native_workers.compile_worker',side_effect=self.fake_worker))
        self.patch(patch('looktool.nameworker.compile_worker',side_effect=self.fake_names_compile))
        self.patch(patch.object(mod,'_prepare_native_sync',side_effect=self.fake_sync))
        self.real_wbi_provenance=mod._wbi_provenance
        self.patch(patch.object(mod,'_wbi_provenance',return_value={'synthetic_test_only':True}))
        self.patch(patch.object(mod,'_reader_reference',side_effect=lambda path,**kwargs:{'manifest':str(path.relative_to(self.root)),'manifest_sha256':'5'*64,'worker':{'file':'mocked-reader','sha256':'6'*64}}))
        self.patch(patch.object(mod,'_read_sync_catalog',return_value={'manifest':'mocked-catalog','manifest_sha256':'7'*64,
            'recovery_to_st':{},'recovery_from_st':{}}))
        files={'AP.bin':self.original['AP'],'CP.bin':self.original['CP']}
        files.update({name:name.encode() for name in self.snapshots})
        for tag in ('before','after'):
            for kind in ('memory','flash'):
                for key,value in units.items():files[f'{tag}-{kind}-cp-{key:08x}.bin']=value
        resource=(struct.pack('<8sHHI',b'uxc\x07\0\0\0\0',8,5,2860|(2860<<12))+
                  b'\0\0'+b'\xff\xff'*2859+struct.pack('<I',0x1e00a000)+b'ST\0\0')
        self.names=mod._resource_names()
        files.update({'resources/'+name:resource for name in self.names})
        for copy in ('copy-a','copy-b'):
            for name,raw in files.items():
                p=self.folder/copy/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        boot='12345678-1234-1234-1234-123456789abc\n'
        bases=[0]*18;bases[10]=5
        self.checkpoint={'schema':'a7cr-slot1-readonly-checkpoint/1','complete':True,'model':'ILCE-7CR','firmware':'2.01',
            'normal_usb_return_confirmed':True,'firmware_resources_settings_or_wbi_written':False,
            'only_owned_temporary_readers_executed':True,'installation_prepared':False,'resources':68,'copies':['copy-a','copy-b'],
            'body_binding':binding,'utc':'2026-10-24T00:00:00Z','same_physical_volume':True,
            'files':{name:{'bytes':len(raw),'sha256':mod.sha(raw)} for name,raw in files.items()},
            'fields':self.derive_fields(None,self.snapshots['before-memory.bin'],self.snapshots['before-flash.bin']),
            'native_ap_model':{'read_only':True,'only_slot1_may_change':True,'before_bases':bases,'after_bases':bases[:],
                'changed_mask':0,'current':0,'after_current':0,'pid':101,'base':0x50000000,'boot_id':boot},
            'loaded_fl23':{'ok':True,'all_loaded_ap_spans_match_candidate':True,'pid':101,'base':0x50000000,'boot_id':boot}}
        evidence=self.folder/'evidence';evidence.mkdir()
        (evidence/'events.private.json').write_text(json.dumps([{'phase':phase} for phase in (
            'runtime_readonly_cleanup_verified','slot1_readonly_probe_cleanup_verified','normal_usb_returned','SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE')]))
        self.save_checkpoint()

    def patch(self,p):p.start();self.addCleanup(p.stop)
    def save_checkpoint(self):(self.folder/'checkpoint.private.json').write_text(json.dumps(self.checkpoint))
    def derive_fields(self,ap,ram,saved):
        return [{'slot':1,'key':key,'before_ram':ram[0][key].data.hex(),'before_saved':saved[0][key].data.hex(),
                 'after':(b'\0' if key==0x02cf0cd0 else bytes(4)).hex()} for key in sorted(mod.SELECTED_KEYS)]
    def fake_worker(self,folder,filename,text,header=None):
        folder.mkdir(parents=True,exist_ok=True);path=folder/(filename+'.so')
        raw=(filename+'|'+text+'|'+str(header)).encode();path.write_bytes(raw)
        self.compiled.append((filename,text,header))
        return {'file':str(path.relative_to(self.root)),'bytes':len(raw),'sha256':mod.sha(raw),'source_sha256':mod.sha(text.encode())}
    def fake_names_compile(self,source,header,destination,zig=None,**kwargs):
        raw=b'synthetic-native-name-worker';destination.write_bytes(raw)
        return {'sha256':mod.sha(raw),'bytes':len(raw)}
    def fake_sync(self,output,native):
        folder=output/'native-slot-sync';worker=self.fake_worker(folder,'slot1-sync','synthetic-only')
        return {'read_only':False,'expected_before':native['before_bases'][10],'target':0,'require_current_st':False,
                'simulation_passed':False,'worker':worker,'audit':{'guards':[{'offset':0,'bytes':4,'hex':self.target['AP'][:4].hex()}]}}
    def run_prepare(self):return mod.prepare(self.folder,self.output)

    def test_complete_synthetic_preparation_stays_offline_pending_and_preserves_scope(self):
        result=self.run_prepare()
        self.assertEqual(result['schema'],mod.SCHEMA)
        self.assertEqual(result['names'],{'1':'Classic Chrome'})
        self.assertEqual({f['key'] for f in result['settings']},mod.SELECTED_KEYS)
        self.assertEqual(result['native_slot_sync']['expected_before'],5)
        self.assertEqual(result['native_slot_sync']['target'],0)
        self.assertEqual(set(result['resources']),set(self.names))
        self.assertEqual([step.get('worker') for step in result['recovery_order'] if 'worker' in step][:2],['ap_stage','cp_stage'])
        self.assertEqual([step['mode'] for step in result['recovery_order'] if step.get('worker') in ('ap_stage','cp_stage')],[2,2])
        for flag in ('ready_for_write','native_worker_simulation_passed','host_flow_tests_passed','device_preflight_passed','physical_ready','installation_authorized'):
            self.assertIs(result[flag],False)
        self.assertEqual(json.loads((self.output/'state.private.json').read_text())['phase'],'PREPARED_OFFLINE_PENDING_REVIEW')
        header=(self.output/'names/names.private.h').read_text()
        self.assertIn('static const u32 selected_mask=1;',header)
        self.assertTrue(result['resource_old_links_cleanup_requires_physical_acceptance'])
        self.assertTrue(result['no_wholesale_snapshot_restore'])

    def test_refuses_partial_checkpoint_before_any_worker_or_output(self):
        self.checkpoint['complete']=False;self.save_checkpoint();self.compiled.clear()
        with self.assertRaises(ValueError):self.run_prepare()
        self.assertFalse(self.output.exists());self.assertFalse(self.compiled)

    def test_saved_ST_is_not_substitute_for_absent_native_probe(self):
        self.checkpoint.pop('native_ap_model');self.save_checkpoint()
        with self.assertRaisesRegex(ValueError,'native AP model'):self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_different_loaded_boot_or_process_is_rejected(self):
        self.checkpoint['loaded_fl23']['pid']=102;self.save_checkpoint()
        with self.assertRaisesRegex(ValueError,'same current AP'):self.run_prepare()

    def test_corrupt_second_copy_is_rejected(self):
        (self.folder/'copy-b/AP.bin').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'size/digest'):self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_hardlinked_copies_are_not_two_independent_backups(self):
        a=self.folder/'copy-a/AP.bin';b=self.folder/'copy-b/AP.bin';b.unlink();b.hardlink_to(a)
        with self.assertRaisesRegex(ValueError,'share an inode'):self.run_prepare()

    def test_unselected_unsaved_setting_would_be_persisted_and_is_rejected(self):
        for name in ('before-flash.bin','after-flash.bin'):
            self.snapshots[name][0][0x02cf7770].data=b'different'
        with self.assertRaisesRegex(ValueError,'Unselected unsaved'):self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_selected_unsaved_divergence_requires_explicit_replay_protocol(self):
        for name in ('before-flash.bin','after-flash.bin'):
            self.snapshots[name][0][0x02cf0cd0].data=b'\x02'
        self.checkpoint['fields']=self.derive_fields(None,self.snapshots['before-memory.bin'],self.snapshots['before-flash.bin']);self.save_checkpoint()
        with self.assertRaisesRegex(ValueError,'Selected slot unsaved'):self.run_prepare()

    def test_changed_unselected_state_during_capture_is_rejected(self):
        self.snapshots['after-memory.bin'][0][0x02cf7770].data=b'changed'
        with self.assertRaisesRegex(ValueError,'Unrelated property changed'):self.run_prepare()

    def test_protected_CP_snapshot_mismatch_is_rejected(self):
        self.snapshots['after-memory.bin'][1][0x02a40001].data=b'wrong'
        with self.assertRaisesRegex(ValueError,'Protected CP unit'):self.run_prepare()

    def test_final512_resource_tail_is_rejected_without_mirror_guess(self):
        name='resources/'+self.names[0];p=self.folder/'copy-a'/name;raw=p.read_bytes()
        n=((len(raw)+4+511)//512)*512-4
        raw+=bytes(n-len(raw))
        for copy in ('copy-a','copy-b'):(self.folder/copy/name).write_bytes(raw)
        self.checkpoint['files'][name]={'bytes':len(raw),'sha256':mod.sha(raw)};self.save_checkpoint()
        with self.assertRaisesRegex(ValueError,'final512'):self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_missing_cleanup_evidence_is_rejected(self):
        (self.folder/'evidence/events.private.json').write_text(json.dumps([{'phase':'SINGLE_SLOT_READONLY_CHECKPOINT_COMPLETE'}]))
        with self.assertRaisesRegex(ValueError,'cleanup/normal USB'):self.run_prepare()

    def test_cannot_prepare_inside_readonly_checkpoint(self):
        with self.assertRaises(ValueError):mod.prepare(self.folder,self.folder/'prepared')

    def test_native_compile_failure_leaves_explicit_nonready_local_state(self):
        self.patch(patch('build_native_workers.compile_worker',side_effect=RuntimeError('synthetic compiler failure')))
        with self.assertRaises(RuntimeError):self.run_prepare()
        state=json.loads((self.output/'state.private.json').read_text())
        self.assertEqual(state['phase'],'OFFLINE_PREPARATION_FAILED');self.assertIs(state['ready_for_write'],False)

    def test_raw_runtime_reports_are_redecoded_hashed_and_json_drift_is_rejected(self):
        self.raw_evidence_patch.stop()
        reader=self.root/'private/runtime-diagnostic/runtime.private.json';reader.parent.mkdir(parents=True)
        reader.write_text(json.dumps({'spans':[{'offset':i,'bytes':1,'name':str(i)} for i in range(8)]}))
        names=['a7cr.diag.probe.result.private.bin','a7cr.diag.runtime.result.private.bin',
               'slot1-a7cr.diag.probe.result.private.bin','slot1-a7cr.slot1.bindings.result.private.bin']
        for i,name in enumerate(names):(self.folder/'evidence'/name).write_bytes(bytes([i])*32)
        cp=deepcopy(self.checkpoint)
        cp['loaded_fl23']['spans']=[{'loaded_state':'candidate','disk_state':'candidate'} for _ in range(8)]
        original=deepcopy(cp)
        probe={'status':0,'cleanup':0,'pid':101,'base':0x50000000}
        with patch('diagnose_fl23.decode_probe',return_value=probe), \
             patch('diagnose_fl23.decode_runtime',side_effect=lambda *args:deepcopy(original['loaded_fl23'])), \
             patch('single_slot_runtime.decode',side_effect=lambda *args,**kwargs:deepcopy(original['native_ap_model'])):
            result=mod._decode_live_evidence(self.folder,self.baseline,cp)
            self.assertTrue(result['binary_reports_redecoded']);self.assertEqual(set(result['files']),set(names))
            self.assertTrue(all(row['bytes']==32 and len(row['sha256'])==64 for row in result['files'].values()))
            cp['native_ap_model']['before_bases'][10]=4
            with self.assertRaisesRegex(ValueError,'JSON differs'):
                mod._decode_live_evidence(self.folder,self.baseline,cp)
            cp=deepcopy(original);cp['loaded_fl23']['spans'][0]['disk_state']='original'
            original=deepcopy(cp)
            with self.assertRaisesRegex(ValueError,'same current FL23'):
                mod._decode_live_evidence(self.folder,self.baseline,cp)


    def test_wbi_provenance_requires_exact_prior_blobs_and_all_boundary_cases(self):
        folder=self.root/'private/native-workers';folder.mkdir()
        workers=deepcopy(self.baseline.manifest['files'])
        prior={'native_simulation_passed':True,'workers':deepcopy(workers)}
        cases={'wbi-inspect-only':0,'wbi-check-rejects-drop':-22,'wbi-rejects-wrong-start':-22,'wbi-drop-then-mode0':0}
        simulation={'schema':'a7cr-native-syscall-simulation/1','results':[{'case':name,'passed':True,'status':status} for name,status in cases.items()]}
        (folder/'workers.private.json').write_text(json.dumps(prior));(folder/'simulation.private.json').write_text(json.dumps(simulation))
        result=self.real_wbi_provenance(workers)
        self.assertTrue(result['reused_exact_artifacts_without_recompilation']);self.assertTrue(result['mode2_drop_then_mode0_simulated'])
        simulation['results'].pop();(folder/'simulation.private.json').write_text(json.dumps(simulation))
        with self.assertRaisesRegex(ValueError,'boundary case'):self.real_wbi_provenance(workers)
        simulation['results'].append({'case':'wbi-drop-then-mode0','passed':True,'status':0})
        (folder/'simulation.private.json').write_text(json.dumps(simulation))
        prior['workers']['wbi_stage']['sha256']='0'*64;(folder/'workers.private.json').write_text(json.dumps(prior))
        with self.assertRaisesRegex(ValueError,'identity differs'):self.real_wbi_provenance(workers)


    def test_4096_window_chunking_retains_exact_inverse_and_order(self):
        old={'AP':b'A'*10000,'CP':b'C'*10000};new={k:b'B'*10000 for k in old}
        material={'original':old,'candidate':new,'manifest':{'programs':{k:{'bytes':10000,'source_sha256':mod.sha(old[k]),
            'candidate_sha256':mod.sha(new[k]),'windows':[{'offset':0,'bytes':10000,'before_hex':old[k].hex(),'after_hex':new[k].hex(),'purpose':'large'}]} for k in old}}}
        programs,windows=mod._normalized_programs(material)
        self.assertEqual([w['bytes'] for w in programs['CP']['windows']],[4096,4096,1808])
        self.assertTrue(all(w['bytes']<=4096 for w in windows))
        material['manifest']['programs']['CP']['windows'][0]['after_hex']=b'X'.hex()
        with self.assertRaises(ValueError):mod._normalized_programs(material)


if __name__=='__main__':unittest.main()
