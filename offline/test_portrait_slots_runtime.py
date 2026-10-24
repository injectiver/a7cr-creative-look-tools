"""Report ABI/scope and compiled-artifact receipt integrity, all offline."""
from copy import deepcopy
import json
import struct
import unittest

import portrait_slots_runtime as m


def report(*,slot=None,before=5,target=0,current=0,drift=None):
    values=[i%12 for i in range(18)];values[10]=0
    mode=int(slot is not None);mask=0;after=values[:]
    if slot is not None:
        index=m.NATIVE_INDICES[slot];values[index]=before;after=values[:];after[index]=target
        mask=(1<<index) if before!=target else 0
    if drift is not None:after[drift]=9
    raw=bytearray(272)
    struct.pack_into('<8sIIqqQIIII',raw,0,b'A7CPR001',1,mode,0,123,0x50000000,current,current,mask,0)
    struct.pack_into('<18I',raw,56,*values);struct.pack_into('<18I',raw,128,*after)
    boot=b'12345678-1234-1234-1234-123456789abc\n';raw[200:200+len(boot)]=boot
    return raw


class PortraitRuntimeTests(unittest.TestCase):
    def test_readonly_full18_no_mutation(self):
        result=m.decode(report(current=10),read_only=True)
        self.assertEqual(result['before_bases'],result['after_bases'])
        self.assertEqual(result['before_bases'][10],0)
        self.assertIsNone(result['selected_slot'])

    def test_writer_only_correct_new_slot_with_global_st(self):
        for slot in m.SLOTS:
            got=m.decode(report(slot=slot),read_only=False,selected_slot=slot,expected_before=5,target=0,require_current_st=True)
            self.assertEqual(got['after_bases'][m.NATIVE_INDICES[slot]],0)
            self.assertEqual(got['changed_mask'],1<<m.NATIVE_INDICES[slot])
        noop=m.decode(report(slot=2,before=0),read_only=False,selected_slot=2,expected_before=0,target=0,require_current_st=True)
        self.assertEqual(noop['changed_mask'],0)

    def test_recovery_from_st_to_native_current_cc_value(self):
        got=m.decode(report(slot=3,before=0,target=6),read_only=False,selected_slot=3,expected_before=0,target=6,require_current_st=True)
        self.assertEqual(got['after_bases'][12],6)
        self.assertEqual(got['after_bases'][10],0)

    def test_cc_or_unselected_slot_drift_or_cas_mismatch_rejected(self):
        for slot in m.SLOTS:
            for index in (10,13,12 if slot==2 else 11):
                with self.subTest(slot=slot,index=index),self.assertRaises(ValueError):
                    m.decode(report(slot=slot,drift=index),read_only=False,selected_slot=slot,expected_before=5,target=0,require_current_st=True)
            with self.assertRaises(ValueError):m.decode(report(slot=slot,before=6),read_only=False,selected_slot=slot,expected_before=5,target=0,require_current_st=True)

    def test_write_mode_global_st_and_bounded_enums_enforced(self):
        args=dict(read_only=False,selected_slot=2,expected_before=5,target=0,require_current_st=True)
        for update in ({'selected_slot':1},{'selected_slot':4},{'selected_slot':True},{'expected_before':12},
                       {'expected_before':False},{'target':12},{'require_current_st':False},{'read_only':1}):
            with self.subTest(update=update),self.assertRaises(ValueError):m.decode(report(slot=2),**{**args,**update})
        with self.assertRaises(ValueError):m.decode(report(slot=2,current=10),**args)

    def test_bad_abi_status_truncation_and_reserved_bytes_rejected(self):
        raw=report();cases=[raw[:-1]]
        for at,value in ((0,b'A7CST001'),(16,struct.pack('<q',-116)),(48,b'\x01'),(264,b'\x01'),(200,b'old-boot')):
            altered=raw[:];altered[at:at+len(value)]=value;cases.append(altered)
        for altered in cases:
            with self.subTest(altered=altered[:24].hex()),self.assertRaises(ValueError):m.decode(altered,read_only=True)

    def test_generated_header_writes_cannot_target_existing_cc_slot(self):
        audit={'guards':[]};args=dict(read_only=False,selected_slot=2,expected_before=5,target=0,require_current_st=True)
        header=m.header(audit,**args)
        self.assertIn('#define SELECTED_INDEX 11',header)
        for update in ({'selected_slot':1},{'selected_slot':6},{'expected_before':-1},{'require_current_st':False}):
            with self.subTest(update=update),self.assertRaises(ValueError):m.header(audit,**{**args,**update})
        with self.assertRaises(ValueError):m.header(audit,read_only=True,selected_slot=2,expected_before=None,target=None,require_current_st=False)

    def test_complete_compiled_catalog_and_probe_have_pinned_receipts(self):
        if not (m.OUT/'catalog/catalog.private.json').is_file():self.skipTest('Private compiled worker evidence excluded')
        catalog=json.loads((m.OUT/'catalog/catalog.private.json').read_bytes())
        self.assertEqual(catalog['variant_count'],46);self.assertTrue(catalog['simulation_passed'])
        pairs={(x,0) for x in range(12)}|{(0,x) for x in range(12)}
        self.assertEqual(set(catalog['workers']),{f'{slot}:{before}:{target}' for slot in m.SLOTS for before,target in pairs})
        manifests=list(catalog['workers'].values())+[json.loads((m.OUT/'probe/worker.private.json').read_bytes())]
        total=0
        for manifest in manifests:
            worker=manifest['worker'];raw=(m.ROOT/worker['file']).read_bytes()
            self.assertEqual(m.sha(raw),worker['sha256']);self.assertEqual(len(raw),worker['bytes'])
            receipt=(m.ROOT/manifest['simulation_report']).read_bytes()
            self.assertEqual(m.sha(receipt),manifest['simulation_report_sha256'])
            proof=json.loads(receipt)
            self.assertTrue(manifest['simulation_passed']);self.assertTrue(proof['passed'])
            self.assertTrue(proof['actual_compiled_worker_executed']);self.assertFalse(proof['camera_accessed'])
            self.assertFalse(proof['hardware_or_persistence_verified'])
            if not manifest['read_only']:
                self.assertTrue(manifest['require_current_st']);self.assertIn(manifest['selected_slot'],m.SLOTS)
                total+=manifest['simulation_cases']
        self.assertEqual(total,634)


if __name__=='__main__':unittest.main()
