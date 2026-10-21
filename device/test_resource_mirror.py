"""Actual Senser framing at the observed length, and mirror host failure stops."""
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

import read_backup
import resource_mirror as mod
from pmca.usb.sony import SonySenserDevice


class FramingDriver:
    """Model full internal padding and no terminal extra data; no USB."""
    def __init__(self,data):self.data=data;self.at=0;self.header=False;self.pad=False;self.final_extra_reads=0
    def getId(self):return 0x54c,0x336
    def reset(self):pass
    def write(self,data):pass
    def read(self,n):
        if not self.header:
            self.header=True
            return SonySenserDevice.SenserPacketHeader.pack(size=len(self.data),pFunc=0x40,sequence=1,version=0,miconType=0,offsetType=0,response=0)
        if self.pad:
            if n!=512:raise ValueError('Expected internal padding read')
            self.pad=False;return bytes(512)
        if self.at==len(self.data):
            self.final_extra_reads+=1;raise TimeoutError('Terminal response is complete; no extra padding arrived')
        result=self.data[self.at:self.at+n];self.at+=len(result)
        self.pad=len(result)%512==0 and self.at<len(self.data)
        return result


class MirrorCamera:
    def __init__(self,payload,bad_report=False,bad_data=False,previous=False):
        self.healthy=True;self.files={'a7cr.six.boundary.data':b'preserve'} if previous else {}
        self.payload=payload;self.bad_report=bad_report;self.bad_data=bad_data;self.invocations=0
    def read_temp(self,name,optional=False):
        if name not in self.files:
            if optional:return None
            raise ValueError('Expected result missing')
        return self.files[name]
    def check_preload(self):pass
    def write_temp(self,name,raw,expected):
        if expected[name]!=raw:raise ValueError('Unreviewed temp write')
        if name=='libJit.so':
            self.invocations+=1
            self.files['a7cr.six.boundary.result']=struct.pack('<8sII4q2Q32s',b'A7CRM001',1,0,
                -5 if self.bad_report else 0,0,77,0,len(self.payload),123,bytes.fromhex(mod.sha(self.payload)))
            self.files['a7cr.six.boundary.data']=self.payload+(b'x' if self.bad_data else b'\xa7')
        else:self.files[name]=raw
    def remove_temp(self,name,expected):
        if name in self.files:
            if self.files[name]!=expected[name]:raise ValueError('Unexpected temporary contents')
            del self.files[name]


class MirrorTests(unittest.TestCase):
    def test_original_response_shape_requests_missing_terminal_padding(self):
        driver=FramingDriver(bytes(119296));channel=SonySenserDevice(driver)
        with self.assertRaises(TimeoutError):channel.sendSenserPacket(0x40,b'read')
        self.assertEqual(driver.at,119296);self.assertEqual(driver.final_extra_reads,1)
    def test_one_byte_padded_copy_uses_same_parser_without_terminal_read(self):
        data=bytes(119296)+b'\xa7';driver=FramingDriver(data);channel=SonySenserDevice(driver)
        status,result=channel.sendSenserPacket(0x40,b'read')
        self.assertEqual((status,result),(0,data));self.assertEqual(driver.final_extra_reads,0)
    def fixture(self,**options):
        if not mod.MANIFEST.is_file():
            self.skipTest("Private resource-mirror manifest deliberately excluded")
        m=json.loads(mod.MANIFEST.read_text());size=m['source_sizes'][1];payload=bytes((i*7)%256 for i in range(size))
        package=SimpleNamespace(resources={mod.RESOURCE:b'old'},named_resources={mod.RESOURCE:payload})
        return MirrorCamera(payload,**options),package
    def test_full_mirror_verified_and_temp_files_removed(self):
        camera,p=self.fixture()
        with tempfile.TemporaryDirectory() as folder:
            result=mod.read(camera,p,Path(folder),lambda *args,**kwargs:None)
            # A second read gets a separate local evidence file.
            result2=mod.read(camera,p,Path(folder),lambda *args,**kwargs:None)
            self.assertEqual(len(list(Path(folder).glob('boundary-mirror-result-*.bin'))),2)
        self.assertEqual(result,p.named_resources[mod.RESOURCE]);self.assertEqual(result2,result)
        self.assertFalse(camera.files);self.assertTrue(camera.healthy)
    def test_failed_mirror_receipt_stops_without_cleanup_or_repeat(self):
        camera,p=self.fixture(bad_report=True)
        with tempfile.TemporaryDirectory() as folder,self.assertRaises(ValueError):mod.read(camera,p,Path(folder),lambda *args,**kwargs:None)
        self.assertFalse(camera.healthy);self.assertEqual(camera.invocations,1)
        self.assertIn('a7cr.six.boundary.result',camera.files)
    def test_corrupt_mirror_data_stops(self):
        camera,p=self.fixture(bad_data=True)
        with tempfile.TemporaryDirectory() as folder,self.assertRaises(ValueError):mod.read(camera,p,Path(folder),lambda *args,**kwargs:None)
        self.assertFalse(camera.healthy)
    def test_previous_temp_state_blocks_new_invocation(self):
        camera,p=self.fixture(previous=True)
        with tempfile.TemporaryDirectory() as folder,self.assertRaises(ValueError):mod.read(camera,p,Path(folder),lambda *args,**kwargs:None)
        self.assertEqual(camera.invocations,0);self.assertEqual(camera.files['a7cr.six.boundary.data'],b'preserve')


if __name__=='__main__':unittest.main()
