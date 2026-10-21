"""AP-only completion rejects unknown states and preserves fresh preferences."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import complete_six_luts as mod
from install_six_luts import Package
from test_six_luts import FakeCamera,HostJob


class CompletionHostJob(HostJob):
    complete=mod.CompletionJob.complete
    def check_current_programs(self,camera,plan):
        camera.operations.append(('completion_program_check',0));return {'ok':True}


@unittest.skipUnless((mod.ROOT / "private/lut-install/six-20261020-01/package.private.json").is_file(), "Private per-body fixture deliberately excluded from the public release")
class CompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.p=Package()
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='a7cr-completion-test-');self.addCleanup(t.cleanup)
        self.c=FakeCamera(self.p);self.c.programs=self.p.states['cp_only'].copy();self.c.named=True
        self.job=CompletionHostJob(self.p,Path(t.name))
        x=patch.object(mod,'runtime_invoke',return_value={'ok':True,'all_loaded_ap_spans_match_candidate':True})
        x.start();self.addCleanup(x.stop)
    def run_complete(self):self.job.complete(self.c,{})
    def test_only_ap_settings_and_wbi_mutate(self):
        cp=self.c.programs['CP'];self.run_complete()
        self.assertEqual(self.c.programs['CP'],cp)
        self.assertIn(('ap_stage',1),self.c.operations)
        self.assertNotIn(('cp_stage',1),self.c.operations)
        self.assertFalse(any(op[0]=='names' for op in self.c.operations))
        self.assertEqual(self.c.operations[-1],('wbi_stage',1))
        self.assertEqual(self.c.operations.count(('save',0x2cf)),1)
    def test_wrong_cp_stops_before_any_native_action(self):
        self.c.programs['CP']=b'unknown'
        with self.assertRaises(ValueError):self.run_complete()
        self.assertFalse(self.c.operations)
    def test_wrong_ap_stops_before_any_native_action(self):
        self.c.programs['AP']=b'unknown'
        with self.assertRaises(ValueError):self.run_complete()
        self.assertFalse(self.c.operations)
    def test_target_recipe_change_stops_before_ap_write(self):
        key=self.p.fields[0]['key']
        for s in self.c.data.values():s[0][key]=SimpleNamespace(data=b'\x05',attr=s[0][key].attr)
        with self.assertRaises(ValueError):self.run_complete()
        self.assertNotIn(('ap_stage',1),self.c.operations)
    def test_prior_unselected_user_setting_is_preserved(self):
        key=0x02cf00c5
        for s in self.c.data.values():s[0][key]=SimpleNamespace(data=b'\x05',attr=s[0][key].attr)
        self.run_complete()
        self.assertEqual(self.c.data['flash'][0][key].data,b'\x05')
        self.assertNotIn(('write',key),self.c.operations)
    def test_unselected_change_during_preflight_is_not_ignored(self):
        original=self.job.snapshots
        def snapshots(camera,tag):
            if tag=='completion-before-write':
                for s in camera.data.values():s[0][0x02cf00c5]=SimpleNamespace(data=b'\x07',attr=s[0][0x02cf00c5].attr)
            return original(camera,tag)
        self.job.snapshots=snapshots
        with self.assertRaises(ValueError):self.run_complete()
        self.assertNotIn(('ap_stage',1),self.c.operations)
    def test_unknown_ap_result_is_never_repeated(self):
        self.c.fail='ap_stage'
        with self.assertRaises(TimeoutError):self.run_complete()
        self.assertEqual(self.c.operations.count(('ap_stage',1)),1)
        self.assertNotIn(('wbi_stage',1),self.c.operations)
        self.assertFalse(any(op[0]=='write' for op in self.c.operations))
    def test_bad_selected_flash_readback_stops_before_wbi(self):
        original=self.c.save_selected
        def save():
            original();key=self.p.fields[0]['key'];p=self.c.data['flash'][0][key]
            self.c.data['flash'][0][key]=SimpleNamespace(data=b'\xff',attr=p.attr)
        self.c.save_selected=save
        with self.assertRaises(ValueError):self.run_complete()
        self.assertNotIn(('wbi_stage',1),self.c.operations)
    def test_historical_non_target_values_can_change_without_being_written(self):
        old=copy.deepcopy(self.c.data);current=copy.deepcopy(old)
        for s in current.values():s[0][0x02cf00c5]=SimpleNamespace(data=b'\x07',attr=s[0][0x02cf00c5].attr)
        changes=mod.historical_changes(self.p,old,current)
        self.assertEqual(changes['flash'][0]['key'],'02cf00c5')
        self.assertFalse(changes['flash'][0]['write_target'])
    def test_historical_cp_changes_always_reject(self):
        old=copy.deepcopy(self.c.data);current=copy.deepcopy(old);v=current['memory'][1][0x2a40001]
        current['memory'][1][0x2a40001]=SimpleNamespace(data=b'bad',attr=v.attr)
        with self.assertRaises(ValueError):mod.historical_changes(self.p,old,current)
    def test_historical_setting_schema_changes_reject(self):
        old=copy.deepcopy(self.c.data);current=copy.deepcopy(old);v=current['memory'][0][0x02cf00c5]
        current['memory'][0][0x02cf00c5]=SimpleNamespace(data=b'\x07\x01',attr=v.attr)
        with self.assertRaises(ValueError):mod.historical_changes(self.p,old,current)
    def test_real_inspection_readbacks_accepted_with_timeout_retained(self):
        report,snapshots=mod.review_inspection(self.p)
        self.assertTrue(report['original_usb_return_timeout_preserved'])
        self.assertEqual(report['full_resources_verified'],68)
        self.assertEqual(len(report['historical_unselected_changes_preserved']['flash']),8)


if __name__=='__main__':unittest.main()
