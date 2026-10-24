"""Read-only checkpoint source scope and upload rejection checks."""
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import tempfile
import struct
import json
from types import SimpleNamespace

import single_slot_checkpoint as m


@unittest.skipUnless((m.ROOT/'private/install/fl23/payload/candidate-AP.private.bin').is_file(), 'Private per-body firmware fixture excluded')
class SourceScope(unittest.TestCase):
    def setUp(self):
        self.ap=(m.ROOT/'private/install/fl23/payload/candidate-AP.private.bin').read_bytes()

    def test_exact_slot1_descriptor_keys_and_no_input_mutation(self):
        from types import SimpleNamespace
        fields={}
        import struct
        for index in [10]+[0x1520-0x14ea+i*18+shift for i in range(8) for shift in (0,10)]:
            row=struct.unpack_from('<8I',self.ap,0x57c6710+index*32)
            fields[row[1]]=SimpleNamespace(data=b'\x03' if index==10 else (index%10).to_bytes(4,'little'))
        before={k:v.data for k,v in fields.items()}
        plan=m.slot_fields(self.ap,(fields,{}),(fields,{}))
        self.assertEqual(len(plan),9)
        self.assertEqual({r['key'] for r in plan},{0x02cf0cd0,*range(0x02cf0cf0,0x02cf0df0,0x20)})
        self.assertEqual(plan[0]['after'],'00')
        self.assertEqual(before,{k:v.data for k,v in fields.items()})

    def test_unknown_program_rejected_before_parameters(self):
        with self.assertRaisesRegex(ValueError,'Unknown A7CR'):
            m.slot_fields(b'unknown',({},{}),({},{}))


class NoWriterAdmission(unittest.TestCase):
    def test_second_reader_uses_separate_artifacts_and_preserves_first_reader(self):
        from diagnose_fl23 import decode_probe
        # Use a real prior proc-reader ABI, but execute only a fake camera.
        path=m.ROOT/'private/single-slot-checkpoints/slot1-20261024T112811Z/evidence/a7cr.diag.probe.result.private.bin'
        if not path.is_file():self.skipTest('Private diagnostic binary fixture excluded')
        probe=path.read_bytes();identity=decode_probe(probe)
        native=bytearray(272)
        struct.pack_into('<8sIIqqQIIII',native,0,b'A7CSB001',1,0,0,identity['pid'],identity['base'],0,0,0,0)
        struct.pack_into('<18I',native,56,*([0]*18));struct.pack_into('<18I',native,128,*([0]*18))
        boot=b'12345678-1234-1234-1234-123456789abc\n';native[200:200+len(boot)]=boot
        class Camera:
            def __init__(self):self.files={};self.healthy=True
            def read_temp(self,name,optional=False):return self.files.get(name)
            def check_preload(self):pass
            def write_temp(self,name,raw,expected):
                self.files[name]=raw
                if name=='libJit.so':
                    self.files['a7cr.diag.probe.result']=probe
                    self.files['a7cr.slot1.bindings.result']=bytes(native)
            def remove_temp(self,name,expected):
                if name in self.files:
                    if self.files[name]!=expected[name]:raise ValueError('Changed temp')
                    del self.files[name]
        camera=Camera()
        manifest=json.loads((m.ROOT/'private/single-slot-runtime/probe-v2/worker.private.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);first=folder/'a7cr.diag.probe.result.private.bin'
            first.write_bytes(b'original first reader report')
            result=m.invoke_slot_probe(camera,manifest,folder,Mock())
            self.assertTrue(result['read_only'])
            self.assertEqual(first.read_bytes(),b'original first reader report')
            self.assertEqual((folder/'slot1-a7cr.slot1.bindings.result.private.bin').read_bytes(),bytes(native))
            self.assertEqual(camera.files,{})

    def test_writer_or_unsimulated_probe_never_touches_camera(self):
        for manifest in ({'read_only':False,'simulation_passed':True},{'read_only':True,'simulation_passed':False}):
            camera=Mock()
            with self.assertRaises(ValueError):m.invoke_slot_probe(camera,manifest,Path('.'),Mock())
            self.assertEqual(camera.mock_calls,[])

    def test_changed_probe_bytes_never_touch_camera(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'probe.bin').write_bytes(b'unreviewed test module')
            manifest={'read_only':True,'simulation_passed':True,
                      'worker':{'file':'probe.bin','bytes':1,'sha256':'0'*64}}
            camera=Mock()
            with patch.object(m,'ROOT',root),self.assertRaisesRegex(ValueError,'bytes changed'):
                m.invoke_slot_probe(camera,manifest,Path('.'),Mock())
            self.assertEqual(camera.mock_calls,[])



class OwnedReadonlyRecovery(unittest.TestCase):
    def setUp(self):
        self.failed=m.ROOT/'private/single-slot-checkpoints/slot1-20261024T112811Z'
        if not (self.failed/'checkpoint.partial.private.json').is_file():self.skipTest('Private failure history fixture excluded')
        partial=json.loads((self.failed/'checkpoint.partial.private.json').read_text())
        self.package=SimpleNamespace(binding=partial['body_binding'])
        self.manifest=json.loads((m.ROOT/'private/single-slot-runtime/probe-v2/worker.private.json').read_text())
        self.evidence=m.review_readonly_stop(self.failed,self.package,self.manifest)
        prior=self.evidence['loaded_runtime']
        raw=bytearray(272)
        struct.pack_into('<8sIIqqQIIII',raw,0,b'A7CSB001',1,0,0,prior['pid'],prior['base'],0,0,0,0)
        boot=prior['boot_id'].encode();raw[200:200+len(boot)]=boot
        self.slot=bytes(raw)
        # Same report ABI, including proc pid/base; the original first report
        # shares this process with the reviewed second reader.
        self.proc=(self.failed/'evidence/a7cr.diag.probe.result.private.bin').read_bytes()
        self.blob=(m.ROOT/self.manifest['worker']['file']).read_bytes()

    def camera(self,*,bad_module=False,active=False):
        files={'a7cr.slot1-staged.so':b'unknown' if bad_module else self.blob,
               'a7cr.diag.probe.result':self.proc,'a7cr.slot1.bindings.result':self.slot}
        if active:files['libJit.so']=self.blob
        class Camera:
            def __init__(self):self.files=dict(files);self.deleted=[]
            def check_preload(self):pass
            def read_temp(self,name,optional=False):return self.files.get(name)
            def remove_temp(self,name,expected):
                if self.files[name]!=expected[name]:raise ValueError('Mismatch')
                self.deleted.append(name);del self.files[name]
        return Camera()

    def test_exact_readonly_artifacts_archived_before_only_three_owned_deletions(self):
        camera=self.camera()
        with tempfile.TemporaryDirectory() as tmp:
            result=m.cleanup_readonly_stop(camera,self.failed,self.package,self.manifest,Path(tmp),Mock())
            self.assertTrue(result['read_only'])
            self.assertEqual(set(camera.deleted),{'a7cr.slot1-staged.so','a7cr.diag.probe.result','a7cr.slot1.bindings.result'})
            self.assertEqual(len(list(Path(tmp).iterdir())),3)
            self.assertEqual(camera.files,{})

    def test_unknown_module_or_active_entry_never_deleted(self):
        for camera in (self.camera(bad_module=True),self.camera(active=True)):
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    m.cleanup_readonly_stop(camera,self.failed,self.package,self.manifest,Path(tmp),Mock())
                self.assertEqual(camera.deleted,[])

    def test_other_body_and_other_failure_are_not_cleanup_authority(self):
        package=SimpleNamespace(binding={'usb_serial_sha256':'0'*64})
        with self.assertRaises(ValueError):m.review_readonly_stop(self.failed,package,self.manifest)
        with self.assertRaises(ValueError):
            m.review_readonly_stop(m.ROOT/'private/single-slot-checkpoints/slot1-20261024T113539Z',self.package,self.manifest)


if __name__=='__main__':unittest.main()
