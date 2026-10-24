"""Read-only checkpoint field scope and source rejection; no USB session."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

import portrait_slots_checkpoint as m


def fixture():
    descriptors={};items={}
    for slot in (2,3):
        selector=slot+9;key=0x02cf0cd0+2*(slot-1)
        descriptors[selector]=(3,key,0x10000)
        items[key]=SimpleNamespace(data=bytes([slot+3]),attr=0)
        for i in range(8):
            index=0x1520-0x14ea+i*18
            target=0x02cf0cf0+2*(slot-1)+i*0x20;st=0x02cf0cdc+i*0x20
            descriptors[index+selector]=(0,target,0x40000)
            descriptors[index]=(0,st,0x40000)
            items[target]=SimpleNamespace(data=(i+2).to_bytes(4,'little'),attr=0)
            items[st]=SimpleNamespace(data=i.to_bytes(4,'little'),attr=0)
    # Explicitly include retained slot1 to test unsaved/unselected preservation.
    items[0x02cf0cd0]=SimpleNamespace(data=b'\0',attr=0)
    return descriptors,[items,{}],deepcopy([items,{}])


class CheckpointScope(unittest.TestCase):
    def test_exact_eighteen_fields_preserve_inputs(self):
        d,ram,saved=fixture();before=deepcopy(ram)
        result=m.fields_from_descriptors(d.__getitem__,ram,saved)
        expected={0x02cf0cd2,0x02cf0cd4,*range(0x02cf0cf2,0x02cf0df2,0x20),*range(0x02cf0cf4,0x02cf0df4,0x20)}
        self.assertEqual({f['key'] for f in result},expected)
        self.assertEqual({f['slot'] for f in result},{2,3})
        self.assertEqual(ram,before)
        self.assertNotIn(0x02cf0cd0,expected)

    def test_no_uncommitted_selected_recipe_is_accepted(self):
        d,ram,saved=fixture();ram[0][0x02cf0cd2].data=b'\x04'
        with self.assertRaisesRegex(ValueError,'unsaved edits'):
            m.fields_from_descriptors(d.__getitem__,ram,saved)

    def test_unselected_slot1_unsaved_edits_are_not_persisted_later(self):
        d,ram,saved=fixture();ram[0][0x02cf0cd0].data=b'\x01'
        with self.assertRaisesRegex(ValueError,'Unselected unsaved'):
            m.fields_from_descriptors(d.__getitem__,ram,saved)

    def test_bad_descriptor_cannot_expand_write_scope(self):
        d,ram,saved=fixture();d[11]=(3,0x02cf0cd0,0x10000)
        with self.assertRaisesRegex(ValueError,'descriptor'):
            m.fields_from_descriptors(d.__getitem__,ram,saved)

    def test_unknown_base_enum_stops_before_native_writer_is_prepared(self):
        d,ram,saved=fixture();ram[0][0x02cf0cd2].data=saved[0][0x02cf0cd2].data=b'\xff'
        with self.assertRaisesRegex(ValueError,'enum'):
            m.fields_from_descriptors(d.__getitem__,ram,saved)

    def test_wrong_program_rejected_without_backup_inputs(self):
        with self.assertRaisesRegex(ValueError,'Unknown installed'):
            m.slot_fields(b'unknown',({},{}),({},{}))

    def test_same_boot_process_restart_is_rejected(self):
        old={'pid':517,'base':0x50000000,'boot_id':'same-kernel-boot'}
        for key,value in (('pid',518),('base',0x60000000),('boot_id','new-boot')):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'process changed'):
                m.require_same_process(old,{**old,key:value})

    def test_same_process_reports_accepted(self):
        value={'pid':517,'base':0x50000000,'boot_id':'same-kernel-boot'}
        m.require_same_process(value,value.copy())


if __name__=='__main__':unittest.main()
