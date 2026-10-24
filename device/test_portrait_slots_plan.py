"""Pure incremental-scope tests; no camera or USB invocation."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import unittest

import portrait_slots_plan as m
from fl23_install import CP_UNITS


def item(data,attr=0):return SimpleNamespace(data=data,attr=attr)


def fixture():
    fields=[]
    for slot in m.SLOTS:
        for i,key in enumerate(m.SLOT_KEYS[slot]):
            before=bytes([slot+3]) if i==0 else (i+slot).to_bytes(4,'little')
            target=b'\0' if i==0 else (i-1).to_bytes(4,'little')
            fields.append(dict(slot=slot,key=key,before_ram=before.hex(),before_saved=before.hex(),after=target.hex()))
    ap={f['key']:item(bytes.fromhex(f['before_saved'])) for f in fields}
    ap.update({0x02cf0cd0:item(b'\0'),0x02cf0cd1:item(bytes(range(13)),0xc0),
               0x02cf0cd6:item(b'\x07'),0x02cf1287:item(b'\x0a'),0x02cf1289:item(b'\x0b')})
    ap.update({key:item(bytes(range(13)),0xc0) for key in m.COMPANION_KEYS.values()})
    return fields,[ap,{key:item(b'calibration'+bytes([i])) for i,key in enumerate(CP_UNITS)}]


def probe():
    values=[i%12 for i in range(18)];values[10]=0
    return dict(read_only=True,before_bases=values,after_bases=values[:],changed_mask=0,
                current=0,after_current=0,pid=123,base=0x50000000,
                boot_id='12345678-1234-1234-1234-123456789abc\n')


class PortraitPlanTests(unittest.TestCase):
    def setUp(self):self.fields,self.state=fixture()

    def staged(self):
        result=deepcopy(self.state)
        for f in self.fields:result[0][f['key']].data=bytes.fromhex(f['after'])
        return result

    def test_exactly_two_new_slots_eighteen_fields(self):
        self.assertTrue(m.validate_fields(self.fields))
        self.assertEqual({f['slot'] for f in self.fields},{2,3})
        self.assertNotIn(0x02cf0cd0,m.SELECTED_KEYS)

    def test_reject_duplicate_missing_foreign_and_unsaved_fields(self):
        cases=[]
        duplicate=deepcopy(self.fields);duplicate[-1]=deepcopy(duplicate[0]);cases.append(duplicate)
        cases.append(self.fields[:-1])
        foreign=deepcopy(self.fields);foreign[0]['key']=0x02cf0cd0;cases.append(foreign)
        unsaved=deepcopy(self.fields);unsaved[0]['before_ram']='08';cases.append(unsaved)
        invalid=deepcopy(self.fields);invalid[0]['before_saved']=invalid[0]['before_ram']='0c';cases.append(invalid)
        for fields in cases:
            with self.subTest(fields=fields[:1]),self.assertRaises(m.ReviewRequired):m.validate_fields(fields)

    def test_descriptor_api_delegates_parent_checkpoint(self):
        with patch('portrait_slots_checkpoint.slot_fields',return_value=self.fields) as derive:
            self.assertEqual(m.slot_fields(b'ap',self.state,self.state),self.fields)
            derive.assert_called_once_with(b'ap',self.state,self.state)

    def test_preserve_current_cc_other_slots_fl23_and_calibration(self):
        target={f['key']:bytes.fromhex(f['after']) for f in self.fields}
        report=m.selected_preservation(self.state,self.staged(),target)
        self.assertEqual(report['selected_portrait_fields_verified'],18)
        self.assertEqual(report['preserved_slots'],[1,4,5,6])
        for chip,key in ((0,0x02cf0cd0),(0,0x02cf0cd1),(0,0x02cf0cd6),(0,0x02cf1287),(0,0x02cf1289),(1,next(iter(CP_UNITS)))):
            altered=self.staged();altered[chip][key].data=b'foreign'
            with self.subTest(chip=chip,key=key),self.assertRaises(ValueError):m.selected_preservation(self.state,altered,target)

    def test_native_companion_changed_elements_only_to_guarded_target(self):
        after=deepcopy(self.state);key=m.COMPANION_KEYS[2]
        array=bytearray(after[0][key].data);array[4]=0;after[0][key].data=bytes(array)
        m.selected_preservation(self.state,after,{},native_targets={2:0})
        for targets in ({},{3:0},{2:5},{1:0}):
            with self.subTest(targets=targets),self.assertRaises(m.ReviewRequired):m.selected_preservation(self.state,after,{},native_targets=targets)

    def test_companion_attr_length_and_existing_cc_companion_fail(self):
        for key,kind in ((m.COMPANION_KEYS[2],'attr'),(m.COMPANION_KEYS[2],'size'),(0x02cf0cd1,'data')):
            after=deepcopy(self.state)
            if kind=='attr':after[0][key].attr=0
            elif kind=='size':after[0][key].data=bytes(12)
            else:after[0][key].data=bytes(13)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.selected_preservation(self.state,after,{},native_targets={2:0})

    def test_no_selected_or_companion_raw_write_allowlist_expansion(self):
        for key in (0x02cf0cd0,m.COMPANION_KEYS[2],0x02cf1287):
            with self.subTest(key=key),self.assertRaises(m.ReviewRequired):m.selected_preservation(self.state,self.state,{key:b'\0'})

    def test_cas_restore_checkpoint_values_from_imported_fields(self):
        staged=self.staged();desired,kept=m.restore_values(self.fields,staged,deepcopy(staged))
        self.assertFalse(kept)
        self.assertEqual(desired,{f['key']:bytes.fromhex(f['before_saved']) for f in self.fields})

    def test_restore_preserves_later_user_edits_and_supported_base(self):
        staged=self.staged();key=m.SLOT_KEYS[3][4];base=m.BASE_KEYS[2]
        staged[0][key].data=b'\x21\0\0\0';staged[0][base].data=b'\x09'
        desired,kept=m.restore_values(self.fields,staged,deepcopy(staged))
        self.assertEqual(desired[key],staged[0][key].data);self.assertEqual(desired[base],b'\x09')
        self.assertEqual(set(kept),{key,base})

    def test_restore_rejects_unsaved_user_edit_or_malformed_layout(self):
        staged=self.staged();saved=deepcopy(staged);key=m.SLOT_KEYS[2][2]
        saved[0][key].data=b'\x09\0\0\0'
        with self.assertRaises(m.ReviewRequired):m.restore_values(self.fields,staged,saved)
        for data in (b'',b'12345'):
            broken=deepcopy(staged);broken[0][key].data=data
            with self.subTest(data=data),self.assertRaises(m.ReviewRequired):m.restore_values(self.fields,broken,deepcopy(broken))

    def test_restore_rejects_unknown_native_base(self):
        staged=self.staged();staged[0][m.BASE_KEYS[3]].data=b'\x0c'
        with self.assertRaises(m.ReviewRequired):m.restore_values(self.fields,staged,deepcopy(staged))

    def test_readonly_full18_model_and_global_st_required(self):
        original=probe();m.validate_probe(original,require_global_st=True)
        for updates in ({'read_only':False},{'changed_mask':1},{'after_current':1},{'before_bases':[0]*17},
                        {'pid':0},{'boot_id':'old'},{'before_bases':[12]*18,'after_bases':[12]*18}):
            broken={**deepcopy(original),**updates}
            with self.subTest(updates=updates),self.assertRaises(m.ReviewRequired):m.validate_probe(broken)
        original['current']=original['after_current']=10
        m.validate_probe(original)
        with self.assertRaises(m.ReviewRequired):m.validate_probe(original,require_global_st=True)

    def test_reprobe_allows_unchanged_or_already_st_only_selected_slot(self):
        for slot in m.SLOTS:
            old=probe();index=m.NATIVE_INDICES[slot];before=old['before_bases'][index]
            m.validate_reprobe(old,deepcopy(old),slot,{before,0})
            new=deepcopy(old);new['before_bases'][index]=new['after_bases'][index]=0
            m.validate_reprobe(old,new,slot,{before,0})

    def test_reprobe_rejects_cc_peer_slot_process_boot_and_selection_drift(self):
        old=probe()
        for index in (10,12,13):
            new=deepcopy(old);new['before_bases'][index]=new['after_bases'][index]=9
            with self.subTest(index=index),self.assertRaises(m.ReviewRequired):m.validate_reprobe(old,new,2,{0,old['before_bases'][11]})
        for key,value in (('pid',456),('base',0x51000000),('boot_id','abcdefab-1234-1234-1234-123456789abc\n')):
            new=deepcopy(old);new[key]=value
            with self.subTest(key=key),self.assertRaises(m.ReviewRequired):m.validate_reprobe(old,new,2,{0,old['before_bases'][11]})

    def test_full_program_hash_classification_never_recovers_unknown(self):
        target={'AP':'new AP','CP':'new CP'}
        cases=((m.SOURCE_HASHES,'original'),({'AP':m.SOURCE_HASHES['AP'],'CP':'new CP'},'cp_only'),
               (target,'installed'),({'AP':'new AP','CP':m.SOURCE_HASHES['CP']},'unknown'),
               ({'AP':'foreign','CP':'new CP'},'unknown'))
        for actual,label in cases:self.assertEqual(m.classify_programs(actual,target),label)
        with self.assertRaises(m.ReviewRequired):m.recovery_steps('unknown')

    def test_recovery_deactivates_both_before_ap_then_cp_then_names(self):
        plan=m.recovery_steps('installed');steps=plan['steps'];actions=[step['action'] for step in steps]
        self.assertEqual(plan['recover_to_program_sha256'],m.SOURCE_HASHES)
        self.assertFalse(plan['executable']);self.assertFalse(plan['whole_snapshot_restore'])
        self.assertFalse(plan['physical_recovery_verified'])
        self.assertLess(actions.index('save_ST_reprobe_and_guarded_native_sync'),actions.index('inverse_program'))
        self.assertEqual([s['component'] for s in steps if s['action']=='inverse_program'],['AP','CP'])
        self.assertGreater(actions.index('inverse_only_added_names_after_source_AP'),max(i for i,s in enumerate(steps) if s['action']=='inverse_program'))
        self.assertEqual(plan['preserve_slots'],[1,4,5,6])

    def test_partial_recovery_only_inverses_cp_and_original_neither_program(self):
        cp=m.recovery_steps('cp_only',named=False)
        self.assertEqual([s['component'] for s in cp['steps'] if s['action']=='inverse_program'],['CP'])
        original=m.recovery_steps('original',named=False)
        self.assertFalse(any(s['action']=='inverse_program' for s in original['steps']))


if __name__=='__main__':unittest.main()
