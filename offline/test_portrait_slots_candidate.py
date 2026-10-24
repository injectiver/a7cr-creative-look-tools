"""Offline incremental preservation and actual CPU checks for two portrait looks."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

import portrait_slots_candidate as mod
from looktool import six


def ready():
    return (mod.CURRENT_PACKAGE/'package.private.json').is_file() and all((mod.INPUTS/f'fit-slot{slot}/slot.raw-s8.private.bin').is_file() for slot in (2,3))


@unittest.skipUnless(ready(),'Exact private current CC/DCP fixtures deliberately excluded from public source')
class PortraitCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current,cls.fl23,cls.source=mod.load_current()
        cls.tables,cls.fits=mod.load_fitted_tables()
        cls.target,cls.report=mod.build_candidate(cls.current,cls.tables)

    def test_only_two_slots_added_existing_CC_and_other_banks_remain_exact(self):
        self.assertEqual(self.report['selected_mask'],7)
        self.assertEqual(self.report['added_slots'],[2,3])
        self.assertEqual(self.report['preserve_slots'],[1,4,5,6])
        self.assertEqual(self.report['resource_renames'],{'2':'PRO Neg. Std','3':'ASTIA / SOFT'})
        a,b=six.read_tables(self.current['CP']),six.read_tables(self.target['CP'])
        self.assertEqual(b[0],a[0]);self.assertEqual(b[1],self.tables[2]);self.assertEqual(b[2],self.tables[3]);self.assertEqual(b[3:],a[3:])
        self.assertEqual(self.target['CP'][0x8008:0x800c],self.current['CP'][0x8008:0x800c])
        for slot in (1,4,5,6):
            at=0x59896f0+(slot-1)*0xb8
            self.assertEqual(self.target['AP'][at-32:at+36],self.current['AP'][at-32:at+36])

    def test_exact_inverse_restores_current_CC_not_factory_or_plain_FL23(self):
        for kind in ('AP','CP'):
            inverse=bytearray(self.target[kind]);forward=bytearray(self.current[kind]);last=0
            for window in self.report['programs'][kind]['windows']:
                at,n=window['offset'],window['bytes']
                self.assertGreaterEqual(at,last);last=at+n
                self.assertEqual(self.current[kind][at:at+n],bytes.fromhex(window['before_hex']))
                self.assertEqual(self.target[kind][at:at+n],bytes.fromhex(window['after_hex']))
                inverse[at:at+n]=bytes.fromhex(window['before_hex']);forward[at:at+n]=bytes.fromhex(window['after_hex'])
            self.assertEqual(bytes(inverse),self.current[kind]);self.assertEqual(bytes(forward),self.target[kind])
            self.assertNotEqual(mod.sha(inverse),mod.sha(self.fl23[kind]))

    def test_incremental_scope_only_mask_words_labels2_3_and_table2_3(self):
        a=self.report['programs']['AP']['windows'];c=self.report['programs']['CP']['windows']
        self.assertEqual([w['offset'] for w in a],[mod.single.AP_ENTRY+24,mod.single.AP_ENTRY+96,0x59896f0+0xb8,0x59896f0+2*0xb8])
        self.assertEqual([w['bytes'] for w in a],[4,4,4,4])
        self.assertEqual([(w['offset'],w['bytes']) for w in c],[(0x800c,4),(0x8010,4),(0x8020+1215,1215),(0x8020+2430,1215)])
        self.assertEqual(self.current['CP'][0x20124:0x20154],self.target['CP'][0x20124:0x20154])

    def test_native_actual_mask_title_cached_upload_CC_and_FL23_paths(self):
        report=mod.verify_native(self.current,self.target,self.report,self.fl23)
        self.assertTrue(report['passed']);self.assertEqual(report['ap_instruction_cases'],244)
        self.assertEqual(report['cp_controller_cases'],75);self.assertEqual(report['gamma_cases'],512)
        self.assertTrue(report['CC_native_controller_behavior_preserved'])

    def test_accidentally_enabled_slots4_6_are_detected_by_actual_AP_instructions(self):
        from build_lut_candidate import ap_code
        bad=dict(self.target);ap=bytearray(bad['AP']);ap[mod.single.AP_ENTRY:mod.single.AP_END]=ap_code(63)[0];bad['AP']=bytes(ap)
        report=deepcopy(self.report);report['programs']['AP']['candidate_sha256']=mod.sha(bad['AP'])
        with self.assertRaisesRegex(ValueError,'mask7 converter'):
            mod.verify_native(self.current,bad,report,self.fl23)

    def test_CC_drift_even_with_valid_new_checksum_is_detected(self):
        tables=six.read_tables(self.target['CP']);changed=bytearray(tables[0]);changed[0]^=1;tables[0]=bytes(changed)
        bad=dict(self.target);cp=bytearray(bad['CP']);prefix=six.prefix(tables);cp[0x8000:0x8000+len(prefix)]=prefix;bad['CP']=bytes(cp)
        report=deepcopy(self.report);report['programs']['CP']['candidate_sha256']=mod.sha(bad['CP'])
        with self.assertRaisesRegex(ValueError,'CC CP behavior'):
            mod.verify_native(self.current,bad,report,self.fl23)

    def test_source_mutation_and_wrong_slot_set_are_rejected(self):
        bad=dict(self.current);bad['AP']=bytes([bad['AP'][0]^1])+bad['AP'][1:]
        with self.assertRaisesRegex(ValueError,'Exact installed CC'):mod.build_candidate(bad,self.tables)
        for tables in ({2:self.tables[2]},{1:self.tables[2],2:self.tables[3]},dict(self.tables,**{'3':self.tables[3]})):
            with self.assertRaises(ValueError):mod.build_candidate(self.current,tables)

    def test_invalid_range_or_length_never_enters_firmware(self):
        for raw in (bytes(1214),b'\x40'*1215,b'\xbf'*1215):
            bad=dict(self.tables);bad[2]=raw
            with self.assertRaises(ValueError):mod.build_candidate(self.current,bad)

    def test_current_CC_is_reproduced_and_same_provisional_model_is_explicit(self):
        self.assertTrue(self.source['reproduced_CC_from_reviewed_FL23'])
        self.assertEqual(self.fits['2']['model_sha256'],self.fits['3']['model_sha256'])
        self.assertIs(self.fits['2']['measured_A7CR_accuracy_verified'],False)
        self.assertIs(self.report['installable'],False);self.assertIs(self.report['device_install_eligible'],False)
        self.assertIs(self.report['physical_camera_tested'],False)

    def test_cannot_overwrite_existing_candidate_or_write_outside_private(self):
        with self.assertRaises(ValueError):mod.prepare(mod.OUT)
        with self.assertRaises(ValueError):mod.prepare(Path('/tmp/unapproved-portrait-output'))


if __name__=='__main__':unittest.main()
