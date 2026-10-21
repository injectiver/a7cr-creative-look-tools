"""Six-look host sequencing and preservation with the fresh private checkpoint."""
import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_six_luts as mod
from verify_six_luts import validate_post_state


class FakeCamera:
    def __init__(self,p):
        self.package=p;self.identity={'usb_serial_sha256':p.binding['usb_serial_sha256']}
        self.programs=p.programs['original'].copy();self.named=False;self.healthy=True
        self.data={k:mod.backup_sections(p.source('before-'+k)) for k in ('memory','flash')}
        self.operations=[];self.fail=None
    def read_program(self,path):return self.programs[next(k for k,v in mod.PATHS.items() if v==path)]
    def read_resource(self,name):return (self.package.named_resources if self.named else self.package.resources)[name]
    def write_selected(self,key,value):
        self.operations.append(('write',key));old=self.data['memory'][0][key]
        self.data['memory'][0][key]=SimpleNamespace(data=value,attr=old.attr)
    def save_selected(self):
        self.operations.append(('save',0x2cf))
        for key,prop in self.data['memory'][0].items():
            if key>>16==0x2cf and key!=0x2cf0b6e:self.data['flash'][0][key]=copy.deepcopy(prop)


class HostJob(mod.Job):
    def __init__(self,p,attempt):super().__init__(p,attempt);self.phases=[]
    def record(self,phase,**details):self.events.append(dict(phase=phase,**details))
    def phase(self,phase,**details):self.phases.append(phase);self.record(phase,**details)
    def capture(self,name,raw):self.record('simulated_checkpoint_capture',file=name)
    def snapshots(self,camera,tag):return copy.deepcopy(camera.data)
    def native(self,camera,kind,mode):
        camera.operations.append((kind,mode))
        if camera.fail==kind:camera.healthy=False;raise TimeoutError('Synthetic unknown native outcome')
        if kind=='cp_stage':camera.programs=self.package.states['cp_only'].copy()
        if kind=='ap_stage':camera.programs=self.package.states['installed'].copy()
        return {'ok':True}
    def names_native(self,camera,mode):
        camera.operations.append(('names',mode))
        if mode==1:
            if camera.fail=='names':camera.healthy=False;raise TimeoutError('Synthetic unknown name outcome')
            camera.named=True
        return {'native_verified':True}


@unittest.skipUnless((mod.ROOT / "private/lut-install/six-20261020-01/package.private.json").is_file(), "Private per-body fixture deliberately excluded from the public release")
class SixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.p=mod.Package()
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='a7cr-six-test-');self.addCleanup(temp.cleanup)
        self.c=FakeCamera(self.p);self.j=HostJob(self.p,Path(temp.name))
        self.live=patch.object(mod,'runtime_invoke',return_value={'ok':True,'all_loaded_ap_spans_match_candidate':True})
        self.live.start();self.addCleanup(self.live.stop)
    def test_success_order_only_selected_fields_single_save_and_wbi_last(self):
        self.j.install(self.c)
        mutations=[x for x in self.c.operations if x[0] in ('cp_stage','ap_stage','names','wbi_stage')]
        self.assertEqual(mutations,[('names',0),('cp_stage',1),('names',1),('ap_stage',1),('wbi_stage',1)])
        writes=[x[1] for x in self.c.operations if x[0]=='write']
        self.assertTrue(set(writes)<={f['key'] for f in self.p.fields})
        self.assertFalse({0x02cf1287,0x02cf1288,0x02cf1289,0x02cf128a}&set(writes))
        self.assertEqual(self.c.operations.count(('save',0x2cf)),1)
        self.assertEqual(self.j.phases[-1],'WBI_INVALIDATED_VERIFIED')
    def test_wrong_body_stops_before_native(self):
        self.c.identity['usb_serial_sha256']='wrong'
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertFalse(self.c.operations)
    def test_unknown_program_stops_before_native(self):
        self.c.programs['CP']=b'unknown'
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertFalse(self.c.operations)
    def test_selected_recipe_change_stops_before_native(self):
        key=self.p.fields[0]['key']
        for source in self.c.data.values():source[0][key]=SimpleNamespace(data=b'\x05',attr=source[0][key].attr)
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertFalse(self.c.operations)
    def test_st_recipe_change_stops_before_native(self):
        # ST contrast is the source for all selected custom-slot contrasts.
        key=0x02cf0cdc
        for source in self.c.data.values():source[0][key]=SimpleNamespace(data=(7).to_bytes(4,'little'),attr=source[0][key].attr)
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertFalse(self.c.operations)
    def test_stale_loaded_ap_stops_before_program_mutation(self):
        with patch.object(mod,'runtime_invoke',return_value={'ok':True,'all_loaded_ap_spans_match_candidate':False}):
            with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertFalse(self.c.operations)
    def test_unknown_cp_result_never_repeats_or_proceeds(self):
        self.c.fail='cp_stage'
        with self.assertRaises(TimeoutError):self.j.install(self.c)
        self.assertEqual(self.c.operations.count(('cp_stage',1)),1)
        self.assertNotIn(('names',1),self.c.operations);self.assertNotIn(('ap_stage',1),self.c.operations)
        self.assertFalse(self.c.healthy)
    def test_unknown_names_result_stops_before_ap_and_settings(self):
        self.c.fail='names'
        with self.assertRaises(TimeoutError):self.j.install(self.c)
        self.assertNotIn(('ap_stage',1),self.c.operations)
        self.assertFalse(any(x[0]=='write' for x in self.c.operations))
    def test_unknown_ap_result_stops_before_settings_wbi(self):
        self.c.fail='ap_stage'
        with self.assertRaises(TimeoutError):self.j.install(self.c)
        self.assertNotIn(('wbi_stage',1),self.c.operations)
        self.assertFalse(any(x[0]=='write' for x in self.c.operations))
    def test_unrelated_saved_setting_change_is_preserved(self):
        key=next(k for k,v in self.c.data['memory'][0].items() if k>>16==0x2cf and k not in {f['key'] for f in self.p.fields} and k!=0x2cf0b6e and len(v.data)==4 and k!=0x2cf0cdc)
        expected=(11).to_bytes(4,'little')
        for source in self.c.data.values():source[0][key]=SimpleNamespace(data=expected,attr=source[0][key].attr)
        self.j.install(self.c)
        self.assertEqual(self.c.data['flash'][0][key].data,expected)
        self.assertNotIn(('write',key),self.c.operations)
    def test_session_rejects_calibration_and_mr_writes(self):
        session=mod.Session(self.p,lambda *args,**kwargs:None)
        for key in (0x02a40001,0x02cf1288,0x02cf128a,0x02770015,0x02cf0b6e):
            with self.assertRaises(ValueError):session.write_selected(key,b'\0')
    def test_bad_selected_flash_readback_stops_before_wbi(self):
        save=self.c.save_selected
        def bad_save():
            save();key=self.p.fields[0]['key'];old=self.c.data['flash'][0][key]
            self.c.data['flash'][0][key]=SimpleNamespace(data=b'\xff',attr=old.attr)
        self.c.save_selected=bad_save
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertNotIn(('wbi_stage',1),self.c.operations)
    def test_unselected_cp_change_stops_before_wbi(self):
        save=self.c.save_selected
        def bad_save():
            save();old=self.c.data['flash'][1][0x02a40001]
            self.c.data['flash'][1][0x02a40001]=SimpleNamespace(data=b'bad',attr=old.attr)
        self.c.save_selected=bad_save
        with self.assertRaises(ValueError):self.j.install(self.c)
        self.assertNotIn(('wbi_stage',1),self.c.operations)
    def test_attribute_change_in_selected_field_is_rejected(self):
        before=self.c.data['memory'];after=copy.deepcopy(before)
        for f in self.p.fields:
            old=after[0][f['key']];after[0][f['key']]=SimpleNamespace(data=bytes.fromhex(f['after']),attr=old.attr)
        key=self.p.fields[0]['key'];old=after[0][key]
        after[0][key]=SimpleNamespace(data=old.data,attr=old.attr^1)
        with self.assertRaises(ValueError):mod.selected_preservation(before,after,self.p.fields)
    def test_runtime_telemetry_change_is_diagnostic_only(self):
        before=self.c.data['memory'];after=copy.deepcopy(before)
        for f in self.p.fields:
            old=after[0][f['key']];after[0][f['key']]=SimpleNamespace(data=bytes.fromhex(f['after']),attr=old.attr)
        key=0x02770015;old=after[0][key]
        after[0][key]=SimpleNamespace(data=(9999).to_bytes(len(old.data),'little'),attr=old.attr)
        report=mod.selected_preservation(before,after,self.p.fields)
        self.assertEqual(report['selected_fields_verified'],54)
    def post_data(self):
        data=copy.deepcopy(self.c.data)
        for source in data.values():
            for f in self.p.fields:
                old=source[0][f['key']];source[0][f['key']]=SimpleNamespace(data=bytes.fromhex(f['after']),attr=old.attr)
        runtime={'ok':True,'all_loaded_ap_spans_match_candidate':True,'boot_id':'new-boot'}
        return data,runtime
    def test_post_verification_requires_new_boot(self):
        data,runtime=self.post_data();runtime['boot_id']=self.p.checkpoint['loaded_ap']['boot_id']
        with self.assertRaises(ValueError):validate_post_state(self.p,data,runtime)
    def test_post_verification_requires_all_loaded_spans(self):
        data,runtime=self.post_data();runtime['all_loaded_ap_spans_match_candidate']=False
        with self.assertRaises(ValueError):validate_post_state(self.p,data,runtime)
    def test_post_verification_checks_selected_saved_binding(self):
        data,runtime=self.post_data();key=self.p.fields[0]['key']
        data['flash'][0][key]=SimpleNamespace(data=b'\x01',attr=data['flash'][0][key].attr)
        with self.assertRaises(ValueError):validate_post_state(self.p,data,runtime)
    def test_post_verification_preserves_native_fl23(self):
        data,runtime=self.post_data();old=data['memory'][0][0x02cf1287]
        data['memory'][0][0x02cf1287]=SimpleNamespace(data=b'\0',attr=old.attr)
        with self.assertRaises(ValueError):validate_post_state(self.p,data,runtime)
    def test_post_verification_accepts_target_fields_and_new_loaded_boot(self):
        data,runtime=self.post_data();validate_post_state(self.p,data,runtime)


if __name__=='__main__':unittest.main()
