"""Offline protocol-boundary checks; no USB devices are opened."""
import ast
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import read_backup as subject


class ReaderTests(unittest.TestCase):
    def make_reader(self):
        reader = subject.Reader()
        reader.backend = SimpleNamespace(reset=Mock())
        reader.channel = SimpleNamespace(sendSenserPacket=Mock())
        reader.camera = SimpleNamespace(getBackupPresetData=Mock(return_value=b"snapshot"),
                                         _sendAdjustControlPacket=Mock(return_value=bytes(8192)))
        return reader

    def test_prepared_usb_body_mismatch_stops_before_authentication(self):
        reader=subject.Reader();reader.expected_usb_serial_sha256='expected-body'
        usb=SimpleNamespace(core=SimpleNamespace(find=Mock()))
        with (patch.object(subject,'usb_modules',return_value=(usb,object())),
              patch.object(subject,'normal_identity',return_value={'usb_serial_sha256':'another-body'}),
              patch('pmca.usb.sony.SonySenserAuthDevice') as auth):
            with self.assertRaises(ValueError):reader.__enter__()
        auth.assert_not_called();usb.core.find.assert_not_called()

    def test_path_allowlist_rejects_other_files_without_usb(self):
        reader = self.make_reader()
        for path in ("/etc/ld.so.preload", "/usr/lib/../lib/appFw.so", "/dev/nflasha15"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reader.read_program(path)
        reader.channel.sendSenserPacket.assert_not_called()

    def test_program_read_only_selects_and_reads(self):
        reader = self.make_reader()
        reader.channel.sendSenserPacket.side_effect = [(0, bytes(4)), (0, bytes(4)+b"abc")]
        with patch.dict(subject.PROGRAMS, {"/usr/lib/appFw.so": (3, "appFw.so")}):
            self.assertEqual(reader.read_program("/usr/lib/appFw.so"), b"abc")
        calls = reader.channel.sendSenserPacket.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual([int.from_bytes(call.args[1][2:4], "little") for call in calls], [15, 17])

    def test_file_write_delete_and_execute_commands_are_rejected(self):
        reader = self.make_reader()
        for command in (0, 1, 16, 18, 19, 255):
            with self.subTest(command=command), self.assertRaises(ValueError):
                reader.jiritsu(command, b"bad")
        reader.channel.sendSenserPacket.assert_not_called()

    def test_timeout_stops_all_following_commands(self):
        reader = self.make_reader()
        reader.channel.sendSenserPacket.side_effect = TimeoutError("simulated interrupted read")
        with self.assertRaises(TimeoutError):
            reader.jiritsu(15, b"path")
        with self.assertRaises(ValueError):
            reader.snapshot(True)
        self.assertFalse(reader.healthy)
        reader.camera.getBackupPresetData.assert_not_called()
        self.assertEqual(reader.channel.sendSenserPacket.call_count, 1)

    def test_bad_status_does_not_retry(self):
        reader = self.make_reader()
        reader.channel.sendSenserPacket.return_value = (0, b"\x06\0\0\x10")
        with self.assertRaises(ValueError):
            reader.jiritsu(17, b"read")
        self.assertFalse(reader.healthy)
        self.assertEqual(reader.channel.sendSenserPacket.call_count, 1)

    def test_redundant_direct_cp_protocol_is_not_exposed(self):
        reader = self.make_reader()
        self.assertFalse(hasattr(reader, "cp_unit"))
        reader.camera._sendAdjustControlPacket.assert_not_called()

    def test_flash_and_memory_snapshot_reads_are_explicit(self):
        reader = self.make_reader()
        self.assertEqual(reader.snapshot(True), b"snapshot")
        self.assertEqual(reader.snapshot(False), b"snapshot")
        with self.assertRaises(ValueError):
            reader.snapshot(1)
        self.assertEqual([call.args for call in reader.camera.getBackupPresetData.call_args_list], [(True,), (False,)])

    def test_no_persistent_camera_write_api_is_called(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        forbidden = {"writeFile", "deleteFile", "writeMemory", "writeBackup", "saveBackup",
                     "setBackupPresetData", "setBackupId1", "temp_write", "temp_remove"}
        called = {node.func.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(called & forbidden)

    def test_full_mock_backup_produces_two_complete_verified_copies(self):
        reader = self.make_reader()
        reader.identity = {"model": subject.MODEL, "usb_serial_sha256": "synthetic"}
        reader.read_program = Mock(return_value=b"abc")
        reader.snapshot = Mock(return_value=b"synthetic-BK4")
        reader.cp_unit = Mock(return_value=b"xy")
        context = Mock()
        context.__enter__ = Mock(return_value=reader)
        context.__exit__ = Mock(return_value=False)
        ap = {0x00E70003: SimpleNamespace(data=b"\x01\x02\x03\x04")}
        cp = {0x02A40001: SimpleNamespace(data=b"xy")}
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder)/"first", Path(folder)/"second"
            with (patch.object(subject, "Reader", return_value=context),
                  patch.object(subject, "PROGRAMS", {"/usr/lib/appFw.so": (3, "appFw.so")}),
                  patch.object(subject, "CP_UNITS", {0x02A40001: 2}),
                  patch.object(subject, "backup_sections", return_value=[ap, cp]),
                  contextlib.redirect_stdout(io.StringIO())):
                subject.run_backup(first, second, "2.01")
            manifest = json.loads((first/"backup.private.json").read_text())
            self.assertEqual(manifest["phase"], "READ_ONLY_BACKUP_COMPLETE")
            self.assertEqual(len(manifest["files"]), 4)
            for name, info in manifest["files"].items():
                self.assertEqual((first/name).read_bytes(), (second/name).read_bytes())
                self.assertEqual(subject.sha((first/name).read_bytes()), info["sha256"])
            self.assertEqual((first/"backup.private.json").read_bytes(), (second/"backup.private.json").read_bytes())
            reader.cp_unit.assert_not_called()
            reader.camera._sendAdjustControlPacket.assert_not_called()


class IdentityTests(unittest.TestCase):
    def identity(self, product="ILCE-7CR", product_id=0x0E86, interface=8):
        device = SimpleNamespace(idProduct=product_id, iProduct=1, iSerialNumber=2,
                                 get_active_configuration=Mock(return_value={(0, 0): SimpleNamespace(bInterfaceClass=interface)}))
        usb = SimpleNamespace(core=SimpleNamespace(find=Mock(return_value=[device])),
                              util=SimpleNamespace(dispose_resources=Mock(),
                                   get_string=Mock(side_effect=lambda dev, index: product if index == 1 else "SYNTHETIC123456")))
        with patch.object(subject, "usb_modules", return_value=(usb, object())):
            return subject.normal_identity()

    def test_actual_a7cr_pid_is_supported_with_model_and_msc_proof(self):
        identity = self.identity()
        self.assertEqual(identity["model"], "ILCE-7CR")
        self.assertEqual(identity["normal_pid"], 0x0E86)
        self.assertNotIn("SYNTHETIC123456", str(identity))

    def test_a7cii_does_not_pass_on_a_shared_firmware_pid(self):
        with self.assertRaises(ValueError):
            self.identity(product="ILCE-7CM2", product_id=0x0E8A)

    def test_a7cr_in_ptp_mode_is_rejected_before_authentication(self):
        with self.assertRaises(ValueError):
            self.identity(interface=6)


class TransitionTests(unittest.TestCase):
    def fixture(self, snapshots):
        reader = subject.Reader(record=Mock())
        reader.location = (1, (2, 3))
        reader.auth = SimpleNamespace(start=Mock(), authenticate=Mock(), stop=Mock())
        usb = SimpleNamespace(core=SimpleNamespace(find=Mock(side_effect=snapshots)),
                              util=SimpleNamespace(dispose_resources=Mock()))
        return reader, usb

    def device(self, pid, ports=(2, 3)):
        return SimpleNamespace(idProduct=pid, bus=1, port_numbers=ports)

    def clock(self):
        now = [0.0]
        return (patch.object(subject.time, "monotonic", side_effect=lambda: now[0]),
                patch.object(subject.time, "sleep", side_effect=lambda seconds: now.__setitem__(0, now[0]+seconds)))

    def test_observation_tracks_normal_disappearance_and_service_without_reauth(self):
        normal, service = self.device(0x0E86), self.device(subject.SERVICE)
        reader, usb = self.fixture([[normal], [], [service]])
        clock, sleep = self.clock()
        with clock, sleep:
            self.assertIs(reader.wait_for_service(usb, object(), seconds=2), service)
        self.assertTrue(reader.healthy)
        reader.auth.start.assert_not_called(); reader.auth.authenticate.assert_not_called(); reader.auth.stop.assert_not_called()
        observations = [call.kwargs["devices"] for call in reader.record.call_args_list if call.args == ("usb_transition_observed",)]
        self.assertEqual([len(items) for items in observations], [1, 0, 1])

    def test_timeout_with_normal_device_never_retries_or_sends_stop(self):
        normal = self.device(0x0E86)
        reader, usb = self.fixture([[normal], [normal], [normal]])
        clock, sleep = self.clock()
        with clock, sleep, self.assertRaises(TimeoutError):
            reader.wait_for_service(usb, object(), seconds=1)
        self.assertFalse(reader.healthy)
        reader.auth.start.assert_not_called(); reader.auth.authenticate.assert_not_called(); reader.auth.stop.assert_not_called()
        timed_out = [call for call in reader.record.call_args_list if call.args == ("service_transition_timeout",)]
        self.assertEqual(timed_out[0].kwargs["last_observed_pids"], ["0e86"])
        self.assertFalse(timed_out[0].kwargs["authentication_repeated"])

    def test_wrong_port_or_multiple_services_rejected_without_reauth(self):
        for services in ([self.device(subject.SERVICE, (9,))],
                         [self.device(subject.SERVICE), self.device(subject.SERVICE, (9,))]):
            reader, usb = self.fixture([services])
            with self.subTest(count=len(services)), self.assertRaises(ValueError):
                reader.wait_for_service(usb, object())
            self.assertFalse(reader.healthy)
            reader.auth.authenticate.assert_not_called(); reader.auth.stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
