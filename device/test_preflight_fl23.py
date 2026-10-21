"""Offline checks of the preflight's device boundary and unknown-result stops."""
import ast
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import preflight_fl23 as subject


AUDIT = {"programs": {
    "AP": {"source_sha256": "11" * 32, "bytes": 100},
    "CP": {"source_sha256": "22" * 32, "bytes": 200},
}}


def program_report(**changes):
    values = [b"A7IRP001", 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 123,
              21, 22, 100, 200, bytes.fromhex("11" * 32 + "22" * 32), bytes(64)]
    for index, value in changes.items():
        values[int(index)] = value
    return struct.pack("<8s4I7q4Q64s64s", *values)


def wbi_report(**changes):
    values = [b"A7WBR001", 1, 0, 0, 0, 0, 123, 0, 0, 0, 0, 0,
              b"2\n", bytes(16), b"*wbi4\n", bytes(32), 0, 0]
    for index, value in changes.items():
        values[int(index)] = value
    return struct.pack("<8sII9q16s16s32s32sII", *values)


class TempCamera:
    def __init__(self, raw):
        self.raw = raw
        self.files = {}
        self.healthy = True
        self.invocations = 0
        self.removed = []

    def read_temp(self, name, optional=False):
        return self.files.get(name)

    def write_temp(self, name, raw, expected):
        if not self.healthy:
            raise ValueError("Previous result unknown")
        if expected[name] != raw:
            raise AssertionError("Unexpected staging contents")
        self.files[name] = raw
        if name == "libJit.so":
            self.invocations += 1
            if isinstance(self.raw, BaseException):
                raise self.raw
            key = "a7cr.wbi.result" if "a7cr.wbi.request" in self.files else "a7cr.install.result"
            self.files[key] = self.raw
            del self.files[name]

    def check_preload(self):
        pass

    def remove_temp(self, name, expected):
        self.removed.append(name)
        if name in self.files:
            if self.files[name] != expected[name]:
                raise AssertionError("Cleanup touches unexpected contents")
            del self.files[name]


class NativeReportTests(unittest.TestCase):
    def test_program_success_requires_reviewed_whole_programs(self):
        self.assertTrue(subject.decode_program(program_report(), AUDIT)["ok"])
        for change in ({"16": bytes(64)}, {"3": 6}, {"5": -5}, {"10": 1000}, {"12": 0}, {"17": b"x" * 64}):
            with self.subTest(change=change):
                self.assertFalse(subject.decode_program(program_report(**change), AUDIT)["ok"])

    def test_program_install_modes_and_any_write_count_rejected(self):
        for change in ({"2": 1}, {"2": 2}, {"4": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.decode_program(program_report(**change), AUDIT)

    def test_wbi_success_requires_documented_mode_backend_and_no_writes(self):
        self.assertTrue(subject.decode_wbi(wbi_report())["ok"])
        for change in ({"12": b"0\n"}, {"14": b"*wbi3\n"}, {"6": 0}, {"4": -5}, {"16": 1}):
            with self.subTest(change=change):
                self.assertFalse(subject.decode_wbi(wbi_report(**change))["ok"])
        for change in ({"2": 1}, {"7": 1}, {"9": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.decode_wbi(wbi_report(**change))

    def test_truncated_reports_rejected(self):
        for decode, raw in ((lambda raw: subject.decode_program(raw, AUDIT), program_report()),
                            (subject.decode_wbi, wbi_report())):
            for bad in (raw[:-1], raw + b"\0", b""):
                with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                    decode(bad)


class InvocationTests(unittest.TestCase):
    def invoke(self, camera, kind="program_check"):
        with tempfile.TemporaryDirectory() as folder:
            return subject.invoke_check(camera, kind, b"synthetic-worker", Path(folder), Mock(), AUDIT)

    def test_each_check_invoked_once_then_all_owned_files_cleaned(self):
        for kind, raw in (("program_check", program_report()), ("wbi_check", wbi_report())):
            camera = TempCamera(raw)
            self.assertTrue(self.invoke(camera, kind)["ok"])
            self.assertEqual(camera.invocations, 1)
            self.assertFalse(camera.files)
            self.assertTrue(camera.healthy)

    def test_persistent_workers_are_not_dispatchable(self):
        for kind in ("cp_stage", "ap_stage", "wbi_stage", "installer"):
            camera = TempCamera(program_report())
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.invoke(camera, kind)
            self.assertEqual(camera.invocations, 0)
            self.assertFalse(camera.files)

    def test_prior_temporary_state_prevents_new_invocation(self):
        for name in ("libJit.so", "a7cr.install.request", "a7cr.install.result", "a7cr.check-program.so"):
            camera = TempCamera(program_report())
            camera.files[name] = b"previous-job"
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.invoke(camera)
            self.assertEqual(camera.invocations, 0)
            self.assertEqual(camera.files, {name: b"previous-job"})

    def test_unknown_invocation_preserves_state_and_has_no_retry_or_cleanup(self):
        for raw in (TimeoutError("simulated unknown outcome"), b"truncated"):
            camera = TempCamera(raw)
            with self.subTest(raw=raw), self.assertRaises((TimeoutError, ValueError)):
                self.invoke(camera)
            self.assertEqual(camera.invocations, 1)
            self.assertFalse(camera.healthy)
            self.assertFalse(camera.removed)
            self.assertIn("a7cr.install.request", camera.files)

    def test_complete_rejection_is_saved_and_cleaned_without_repeating(self):
        camera = TempCamera(program_report(**{"3": 2, "5": -84}))
        with self.assertRaises(subject.NativeCheckRejected):
            self.invoke(camera)
        self.assertTrue(camera.healthy)
        self.assertEqual(camera.invocations, 1)
        self.assertFalse(camera.files)


class BoundaryTests(unittest.TestCase):
    def session(self):
        camera = subject.CheckSession()
        camera.backend = SimpleNamespace(reset=Mock(), operation_budget_seconds=180)
        camera.camera = SimpleNamespace(_sendAdjustControlPacket=Mock())
        camera.channel = SimpleNamespace(sendSenserPacket=Mock())
        return camera

    def test_only_required_cp_units_use_read40_and_twenty_second_budget(self):
        camera = self.session()
        budgets = []
        camera.backend.reset.side_effect = lambda: budgets.append(camera.backend.operation_budget_seconds)
        for key, size in ((0x02A40001, 8192), (0x02A4000D, 28672)):
            camera.camera._sendAdjustControlPacket.return_value = bytes(size)
            self.assertEqual(len(camera.required_cp_read(key)), size)
            self.assertEqual(camera.camera._sendAdjustControlPacket.call_args.args,
                             (0x603, 0x40, struct.pack("<II", key, 1)))
        self.assertEqual(budgets, [20, 20])
        self.assertEqual(camera.backend.operation_budget_seconds, 180)
        for key in (0x02A40000, 0x02A40002, 0x02CF1287):
            with self.subTest(key=key), self.assertRaises(ValueError):
                camera.required_cp_read(key)
        self.assertEqual(camera.camera._sendAdjustControlPacket.call_count, 2)

    def test_cp_timeout_blocks_all_later_device_commands(self):
        camera = self.session()
        camera.camera._sendAdjustControlPacket.side_effect = TimeoutError("unknown")
        with self.assertRaises(TimeoutError):
            camera.required_cp_read(0x02A40001)
        self.assertFalse(camera.healthy)
        with self.assertRaises(ValueError):
            camera.required_cp_read(0x02A4000D)
        with self.assertRaises(ValueError):
            camera.read_temp("libJit.so", True)
        self.assertEqual(camera.camera._sendAdjustControlPacket.call_count, 1)
        camera.channel.sendSenserPacket.assert_not_called()
        self.assertEqual(camera.backend.operation_budget_seconds, 180)

    def test_unowned_temporary_paths_rejected(self):
        camera = self.session()
        for name in ("../appFw.so", "/sys/power/image_mode", "a7c2.install.request", "other.so"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                camera.select_temp(name)
        camera.channel.sendSenserPacket.assert_not_called()

    def test_no_backup_writes_saves_or_raw_device_access(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        forbidden = {"writeBackup", "saveBackup", "setBackupPresetData", "writeMemory", "writeFile"}
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & forbidden)
        self.assertNotIn("/dev/nflasha", Path(subject.__file__).read_text())

    def test_parameter_preservation_detects_unrelated_changes(self):
        prop = lambda value: SimpleNamespace(data=value, attr=0)
        cp = {key: prop(bytes([index])) for index, key in enumerate(subject.CP_UNITS)}
        before = [{0x02CF1287: prop(b"\0"), 0x02CF0B6E: prop(b"\0")}, cp]
        after = [{0x02CF1287: prop(b"\0"), 0x02CF0B6E: prop(b"\1")}, cp.copy()]
        subject.compare_settings(before, after)
        after[0][0x02CF1287] = prop(b"\x0a")
        with self.assertRaises(ValueError):
            subject.compare_settings(before, after)
        after[0] = before[0]
        after[1][0x02A40002] = prop(b"changed")
        with self.assertRaises(ValueError):
            subject.compare_settings(before, after)


if __name__ == "__main__":
    unittest.main()
