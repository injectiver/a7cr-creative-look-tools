"""Only reviewed stops may attach; no reauthentication or write replay."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import inspect_six_stop as mod
from install_six_luts import Package


@unittest.skipUnless((mod.ROOT / "private/lut-install/six-20261020-01/package.private.json").is_file(), "Private per-body fixture deliberately excluded from the public release")
class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.p=Package()
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(prefix='a7cr-six-review-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);failed=root/mod.FAILED;failed.mkdir()
        source=self.p.root/mod.FAILED
        for name in ['events.private.json','program_check-mode0.private.bin','cp_stage-mode1.private.bin',
                     'wbi_check-mode0.private.bin','names-mode0.private.bin','names-mode1.private.bin']:
            (failed/name).write_bytes((source/name).read_bytes())
        (root/'state.private.json').write_bytes((self.p.root/'state.private.json').read_bytes())
        return SimpleNamespace(root=root,states=self.p.states,programs=self.p.programs,audit=self.p.audit,stores=self.p.stores,
            manifest=self.p.manifest,named_resources=self.p.named_resources),failed
    def test_real_receipts_bind_to_cp_and_names_only(self):
        p,_=self.fixture();report,before=mod.review(p)
        self.assertEqual(report['next_sequence'],485)
        self.assertEqual(report['independent_resources_verified_before_stop'],9)
        self.assertFalse(report['ap_settings_wbi_write_attempted'])
        self.assertEqual(set(before),{'memory','flash'})
    def test_other_stopped_attempt_is_not_eligible(self):
        p,_=self.fixture();s=json.loads((p.root/'state.private.json').read_text());s['attempt']='some-other-attempt'
        (p.root/'state.private.json').write_text(json.dumps(s))
        with self.assertRaises(ValueError):mod.review(p)
    def test_ap_intent_prevents_cp_names_only_recovery(self):
        p,f=self.fixture();events=json.loads((f/'events.private.json').read_text())
        events.insert(-1,dict(phase='native_invocation_intent',worker='ap_stage',mode=1))
        (f/'events.private.json').write_text(json.dumps(events))
        with self.assertRaises(ValueError):mod.review(p)
    def test_missing_host_cp_readback_stops(self):
        p,f=self.fixture();events=json.loads((f/'events.private.json').read_text())
        events=[e for e in events if not(e['phase']=='complete_program_byte_readback' and e.get('tag')=='after-cp' and e.get('chip')=='CP')]
        (f/'events.private.json').write_text(json.dumps(events))
        with self.assertRaises(ValueError):mod.review(p)
    def test_invalid_names_receipt_stops(self):
        p,f=self.fixture();raw=bytearray((f/'names-mode1.private.bin').read_bytes());raw[0]^=1
        (f/'names-mode1.private.bin').write_bytes(raw)
        with self.assertRaises(ValueError):mod.review(p)
    def test_any_saved_settings_write_prevents_this_recovery(self):
        p,f=self.fixture();events=json.loads((f/'events.private.json').read_text())
        events.insert(-1,dict(phase='read_returned',operation='SAVE3_SELECTED_02cf'))
        (f/'events.private.json').write_text(json.dumps(events))
        with self.assertRaises(ValueError):mod.review(p)


class AttachTests(unittest.TestCase):
    def attach(self,*,ports=(2,),kernel=False,serial=b'\x01\x02\x03\x04',devices=1):
        correct=b'\x01\x02\x03\x04'
        package=SimpleNamespace(binding={'ap_serial_sha256':mod.sha(correct.hex().encode('ascii')),'usb_serial_sha256':'synthetic'})
        reviewed=dict(port=dict(bus=2,ports=[2]),next_sequence=485,normal_identity={'model':'ILCE-7CR','normal_pid':0x0e86,'usb_serial_sha256':'synthetic'})
        device=SimpleNamespace(bus=2,port_numbers=ports,idVendor=0x54c,idProduct=0x336,
            is_kernel_driver_active=Mock(return_value=kernel))
        usb=SimpleNamespace(core=SimpleNamespace(find=Mock(return_value=[device]*devices)),
            util=SimpleNamespace(claim_interface=Mock(),dispose_resources=Mock()))
        camera=SimpleNamespace(readBackup=Mock(return_value=serial));auth=SimpleNamespace(start=Mock(),authenticate=Mock(),stop=Mock())
        subject=mod.ExistingService(package,Mock(),reviewed)
        contexts=[patch.object(mod,'usb_modules',return_value=(usb,object())),
            patch('pmca.usb.driver.generic.GenericUsbDriver',return_value=object()),
            patch('pmca.usb.sony.SonySenserDevice',return_value=SimpleNamespace()),
            patch('pmca.usb.sony.SonySenserCamera',return_value=camera),
            patch('pmca.usb.sony.SonySenserAuthDevice',return_value=auth)]
        return subject,camera,auth,usb,contexts
    def run_attach(self,**options):
        from contextlib import ExitStack
        subject,camera,auth,usb,contexts=self.attach(**options)
        with ExitStack() as stack:
            for context in contexts:stack.enter_context(context)
            try:subject.__enter__()
            finally:
                auth.start.assert_not_called();auth.authenticate.assert_not_called();auth.stop.assert_not_called()
        return subject,camera,usb
    def test_attach_only_reads_body_serial_at_next_sequence(self):
        subject,camera,usb=self.run_attach()
        self.assertEqual(subject.channel._sequence,485)
        camera.readBackup.assert_called_once_with(0x00e70003)
        usb.util.claim_interface.assert_called_once()
    def test_wrong_body_stops_without_authentication(self):
        with self.assertRaises(ValueError):self.run_attach(serial=b'bad!')
    def test_wrong_port_stops_without_authentication(self):
        with self.assertRaises(ValueError):self.run_attach(ports=(3,))
    def test_missing_or_ambiguous_service_has_no_normal_auth_fallback(self):
        for devices in (0,2):
            with self.subTest(devices=devices),self.assertRaises(ValueError):self.run_attach(devices=devices)
    def test_kernel_owned_interface_is_not_detached(self):
        with self.assertRaises(ValueError):self.run_attach(kernel=True)


if __name__=='__main__':unittest.main()
