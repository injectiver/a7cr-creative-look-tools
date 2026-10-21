"""Synthetic body transactions and protocol guards; no USB devices opened."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import fl23_install as subject
from test_preflight_fl23 import TempCamera, wbi_report


def prop(raw):
    return SimpleNamespace(data=raw, attr=0)


def fake_package(root):
    old, new = {"AP": b"A"*100, "CP": b"C"*200}, {"AP": b"B"+b"A"*99, "CP": b"D"+b"C"*199}
    units = {"original": {key: bytes(subject.CP_UNITS[key]) for key in subject.CP_KEYS},
             "candidate": {key: bytes([i+1])+bytes(subject.CP_UNITS[key]-1) for i, key in enumerate(subject.CP_KEYS)}}
    audit = {"programs": {kind: {"source_sha256": subject.sha(old[kind]), "candidate_sha256": subject.sha(new[kind]),
                                  "bytes": len(old[kind]), "windows": [{"offset": 0, "bytes": 1,
                                  "before_hex": old[kind][:1].hex(), "after_hex": new[kind][:1].hex()}]}
                            for kind in subject.PATHS}}
    serial = bytes.fromhex("12345678")
    return SimpleNamespace(root=root, audit=audit, units=units, programs={"original": old, "candidate": new},
                           states={"original": old, "cp_only": {"AP": old["AP"], "CP": new["CP"]}, "installed": new},
                           protected={key: bytes(subject.CP_UNITS[key]) for key in subject.CP_UNITS if key not in subject.CP_KEYS},
                           bindings={"original": dict.fromkeys(subject.AP_KEYS, b"\0"),
                                     "candidate": dict(zip(subject.AP_KEYS, (b"\x0a", b"\x0b")))},
                           binding={"usb_serial_sha256": "synthetic-body", "ap_serial_sha256": subject.sha(serial.hex().encode())},
                           blobs=dict.fromkeys(("program_check", "wbi_check", "ap_stage", "cp_stage", "wbi_stage"), b"synthetic-worker"))


def decode_snapshot(raw):
    return [{int(key): prop(bytes.fromhex(value)) for key, value in chip.items()} for chip in json.loads(raw)]


class FakeDevice(subject.Session):
    def __init__(self, package, record, program_state="original", settings="original", fail=None):
        super().__init__(package, record)
        self.identity = {"usb_serial_sha256": "synthetic-body"}
        self.program_bytes = dict(package.states[program_state])
        self.memory = [{0x00E70003: prop(bytes.fromhex("12345678")), 0x02CF1288: prop(b"other-MR-recipe")}, {}]
        self.memory[0].update({key: prop(raw) for key, raw in package.bindings[settings].items()})
        self.memory[1].update({key: prop(raw) for key, raw in package.protected.items()})
        self.memory[1].update({key: prop(raw) for key, raw in package.units[settings].items()})
        self.flash = deepcopy(self.memory)
        self.backend = SimpleNamespace(reset=Mock(), operation_budget_seconds=180)
        self.camera = SimpleNamespace(_sendAdjustControlPacket=self.adjust, writeBackup=self.ap_write,
                                       readBackup=self.ap_read, saveBackup=self.save,
                                       getBackupPresetData=self.get_snapshot)
        self.operations, self.fail, self.mode = [], fail, 2

    def get_snapshot(self, memory):
        source = self.memory if memory else self.flash
        return json.dumps([{str(key): value.data.hex() for key, value in chip.items()} for chip in source]).encode()

    def read_program(self, path):
        if not self.healthy:
            raise ValueError("Unknown prior operation")
        return self.program_bytes[next(key for key, val in subject.PATHS.items() if val == path)]

    def adjust(self, block, command, payload):
        key, chip = struct.unpack_from("<II", payload)
        if block != 0x603 or key not in subject.CP_KEYS or chip != 1:
            raise AssertionError("Unreviewed CP operation")
        self.operations.append(("cp", command, key))
        if command == 0x40:
            if self.fail == "cp-readback" and any(op[:2] == ("cp", 0x41) for op in self.operations):
                return b"wrong-readback"
            return self.memory[1][key].data
        if command != 0x41:
            raise AssertionError("Unsupported CP command")
        self.memory[1][key] = prop(payload[8:])
        if self.fail == "cp-timeout":
            raise TimeoutError("Accepted CP write with lost acknowledgement")
        return b""

    def ap_read(self, key):
        self.operations.append(("ap-read", key))
        return self.memory[0][key].data

    def ap_write(self, key, raw):
        self.operations.append(("ap-write", key))
        self.memory[0][key] = prop(raw)
        if self.fail == "ap-timeout":
            raise TimeoutError("Accepted AP binding write with lost acknowledgement")

    def save(self, group):
        self.operations.append(("save", group))
        for chip in (0, 1):
            for key, value in self.memory[chip].items():
                if key >> 16 == group:
                    self.flash[chip][key] = deepcopy(value)
        if self.fail == "ap-save-corrupt" and group == 0x02CF:
            self.flash[0][subject.AP_KEYS[0]] = prop(b"\0")

    def native(self, package, kind, mode, folder, record):
        if not self.healthy:
            raise AssertionError("Native command after unknown result")
        self.operations.append(("native", kind, mode))
        if kind == "wbi_check":
            if self.mode != 2:
                raise subject.NativeCheckRejected("Wrong initial WBI mode")
        elif kind == "wbi_stage":
            self.mode = 0
        else:
            first, last = ("original", "cp_only") if kind == "cp_stage" else ("cp_only", "installed")
            if mode == 2:
                first, last = last, first
            if self.program_bytes != package.states[first]:
                raise AssertionError("Native stage input differs")
            self.program_bytes = dict(package.states[last])
        return {"ok": True}


def stage_report(package, kind, mode, **changes):
    first, last = ("original", "cp_only") if kind == "cp_stage" else ("cp_only", "installed")
    if mode == 2:
        first, last = last, first
    hashes = lambda state: b"".join(bytes.fromhex(subject.sha(package.states[state][chip])) for chip in subject.PATHS)
    values = [b"A7IRP001", 1, mode, 9, 1, 0, 0, 0, 0, 0, 0, 123, 20, 21, 100, 200, hashes(first), hashes(last)]
    for key, val in changes.items():
        values[int(key)] = val
    return struct.pack("<8s4I7q4Q64s64s", *values)


class WorkflowTests(unittest.TestCase):
    def run_job(self, callback):
        with tempfile.TemporaryDirectory() as folder, patch.object(subject, "backup_sections", side_effect=decode_snapshot):
            root = Path(folder)
            package = fake_package(root)
            attempt = root / "attempt"; attempt.mkdir()
            job = subject.Job(package, attempt)
            camera = FakeDevice(package, job.record)
            with patch.object(subject, "invoke", side_effect=lambda cam, *args: cam.native(*args)), redirect_stdout(io.StringIO()):
                callback(job, camera, package)

    def test_install_dependency_order_saved_targets_and_unrelated_recipe(self):
        def check(job, camera, package):
            before_other = camera.memory[0][0x02CF1288].data
            job.install(camera)
            self.assertEqual(camera.program_bytes, package.states["installed"])
            job.targets({"memory": camera.memory, "flash": camera.flash}, "candidate", "candidate")
            self.assertEqual(camera.memory[0][0x02CF1288].data, before_other)
            native = [op for op in camera.operations if op[0] == "native"]
            self.assertEqual(native, [("native", "wbi_check", 0), ("native", "cp_stage", 1),
                                      ("native", "ap_stage", 1), ("native", "wbi_stage", 1)])
            cp_save = camera.operations.index(("save", 0x02A4))
            ap_stage = camera.operations.index(("native", "ap_stage", 1))
            ap_save = camera.operations.index(("save", 0x02CF))
            wbi = camera.operations.index(("native", "wbi_stage", 1))
            self.assertLess(cp_save, ap_stage); self.assertLess(ap_save, wbi)
            self.assertEqual([op for op in camera.operations if op[0] == "save"], [("save", 0x02A4), ("save", 0x02CF)])
            self.assertEqual(camera.mode, 0)
        self.run_job(check)

    def test_cp_unknown_write_stops_before_save_ap_or_wbi(self):
        def check(job, camera, package):
            camera.fail = "cp-timeout"
            with self.assertRaises(TimeoutError):
                job.install(camera)
            self.assertFalse(camera.healthy)
            writes = [op for op in camera.operations if op[:2] == ("cp", 0x41)]
            self.assertEqual(len(writes), 1)
            self.assertFalse(any(op[0] == "save" or op[:2] in (("native", "ap_stage"), ("native", "wbi_stage")) for op in camera.operations))
            self.assertEqual(camera.operations[-1][:2], ("cp", 0x41))
        self.run_job(check)

    def test_cp_readback_failure_prevents_save_and_later_program_stage(self):
        def check(job, camera, package):
            camera.fail = "cp-readback"
            with self.assertRaises(ValueError):
                job.install(camera)
            self.assertFalse(any(op[0] == "save" or op[:2] == ("native", "ap_stage") for op in camera.operations))
        self.run_job(check)

    def test_saved_ap_mismatch_prevents_wbi(self):
        def check(job, camera, package):
            camera.fail = "ap-save-corrupt"
            with self.assertRaises(ValueError):
                job.install(camera)
            self.assertNotIn(("native", "wbi_stage", 1), camera.operations)
            self.assertEqual(camera.mode, 2)
        self.run_job(check)

    def test_unrelated_unsaved_recipe_stops_before_program_writes(self):
        def check(job, camera, package):
            camera.memory[0][0x02CF1288] = prop(b"unsaved-user-recipe")
            with self.assertRaises(ValueError):
                job.install(camera)
            self.assertFalse(camera.operations)
            self.assertEqual(camera.program_bytes, package.states["original"])
        self.run_job(check)

    def test_wrong_body_and_protected_calibration_prevent_writes(self):
        def check(job, camera, package):
            camera.identity["usb_serial_sha256"] = "another-body"
            with self.assertRaises(ValueError):
                job.install(camera)
            self.assertFalse(camera.operations)
            camera.identity["usb_serial_sha256"] = "synthetic-body"
            camera.memory[1][0x02A40002] = prop(b"different-body-calibration")
            with self.assertRaises(ValueError):
                job.install(camera)
            self.assertFalse(camera.operations)
        self.run_job(check)

    def test_restore_installed_and_cp_only_states_in_inverse_dependency_order(self):
        for state in ("installed", "cp_only"):
            def check(job, camera, package):
                replacement = FakeDevice(package, job.record, program_state=state, settings="candidate")
                self.assertTrue(job.restore(replacement))
                self.assertEqual(replacement.program_bytes, package.states["original"])
                job.targets({"memory": replacement.memory, "flash": replacement.flash}, "original", "original")
                stages = [op[1:] for op in replacement.operations if op[0] == "native"]
                expected = [("wbi_check", 0)]
                if state == "installed":
                    expected += [("ap_stage", 2)]
                expected += [("cp_stage", 2), ("wbi_stage", 1)]
                self.assertEqual(stages, expected)
                self.assertEqual(replacement.memory[0][0x02CF1288].data, b"other-MR-recipe")
            with self.subTest(state=state):
                self.run_job(check)

    def test_restore_original_state_does_not_repeat_writes_or_drop_wbi(self):
        def check(job, camera, package):
            self.assertFalse(job.restore(camera))
            self.assertFalse(camera.operations)
            self.assertEqual(camera.mode, 2)
        self.run_job(check)

    def test_restore_unknown_program_or_parameter_is_rejected(self):
        def check(job, camera, package):
            camera.program_bytes["CP"] = b"unrecognized-program"
            with self.assertRaises(ValueError):
                job.restore(camera)
            self.assertFalse(camera.operations)
        self.run_job(check)
        def unknown_setting(job, camera, package):
            camera.memory[1][subject.CP_KEYS[0]] = prop(b"unknown-unit")
            with self.assertRaises(ValueError):
                job.restore(camera)
            self.assertFalse(camera.operations)
        self.run_job(unknown_setting)

    def prepare_cp_complete(self, camera, package):
        camera.program_bytes = dict(package.states["cp_only"])
        for state in (camera.memory, camera.flash):
            for key, raw in package.units["candidate"].items():
                state[1][key] = prop(raw)
        return {"memory": deepcopy(camera.memory), "flash": deepcopy(camera.flash)}

    def test_explicit_ap_completion_rechecks_then_skips_all_cp_writes_and_save(self):
        def check(job, camera, package):
            reviewed = self.prepare_cp_complete(camera, package)
            job.complete_ap(camera, reviewed)
            self.assertEqual(camera.program_bytes, package.states["installed"])
            job.targets({"memory": camera.memory, "flash": camera.flash}, "candidate", "candidate")
            self.assertEqual([op for op in camera.operations if op[0] == "native"],
                             [("native", "wbi_check", 0), ("native", "ap_stage", 1), ("native", "wbi_stage", 1)])
            self.assertFalse(any(op[:2] == ("cp", 0x41) for op in camera.operations))
            self.assertNotIn(("save", 0x02A4), camera.operations)
        self.run_job(check)

    def test_ap_completion_stops_if_fresh_cp_saved_values_or_ap_binding_differ(self):
        for failure in ("cp-ram", "cp-flash", "ap-binding", "unselected-ap"):
            def check(job, camera, package):
                reviewed = self.prepare_cp_complete(camera, package)
                if failure == "cp-ram":
                    camera.memory[1][subject.CP_KEYS[0]] = prop(package.units["original"][subject.CP_KEYS[0]])
                elif failure == "cp-flash":
                    camera.flash[1][subject.CP_KEYS[0]] = prop(package.units["original"][subject.CP_KEYS[0]])
                elif failure == "ap-binding":
                    camera.memory[0][subject.AP_KEYS[0]] = prop(b"\x0a")
                else:
                    camera.memory[0][0x02CF1288] = prop(b"changed-user-recipe")
                    camera.flash[0][0x02CF1288] = prop(b"changed-user-recipe")
                with self.assertRaises(ValueError):
                    job.complete_ap(camera, reviewed)
                self.assertFalse(camera.operations)
            with self.subTest(failure=failure):
                self.run_job(check)

    def test_ap_completion_unknown_binding_write_stops_before_save_or_wbi(self):
        def check(job, camera, package):
            reviewed = self.prepare_cp_complete(camera, package)
            camera.fail = "ap-timeout"
            with self.assertRaises(TimeoutError):
                job.complete_ap(camera, reviewed)
            self.assertFalse(camera.healthy)
            self.assertEqual(len([op for op in camera.operations if op[0] == "ap-write"]), 1)
            self.assertNotIn(("save", 0x02CF), camera.operations)
            self.assertNotIn(("native", "wbi_stage", 1), camera.operations)
            self.assertFalse(any(op[:2] == ("cp", 0x41) for op in camera.operations))
        self.run_job(check)

    def test_post_restart_verify_only_reads_and_never_installs_saves_or_drops_wbi(self):
        def check(job, camera, package):
            replacement = FakeDevice(package, job.record, program_state="installed", settings="candidate")
            replacement.read_temp = Mock(return_value=None)
            self.assertEqual(job.inspect(replacement, verify=True), "installed")
            self.assertFalse(replacement.operations)
            self.assertEqual(replacement.mode, 2)
            self.assertTrue(any(e["phase"] == "inspection_verified" and not e["loaded_programs_or_photo_behavior_proven"]
                                for e in job.events))
        self.run_job(check)


class PreservationScopeTests(unittest.TestCase):
    def states(self):
        first = [{0x02CF1287: prop(b"\0"), 0x02CF1289: prop(b"\0"), 0x02CF1288: prop(b"keep-recipe"),
                  subject.AP_DIAGNOSTIC: SimpleNamespace(data=bytes(4), attr=64),
                  0x02770015: SimpleNamespace(data=(123).to_bytes(4, "little"), attr=2)},
                 {key: prop(b"keep-calibration") for key in subject.CP_UNITS}]
        return first, deepcopy(first)

    def test_known_02770015_telemetry_and_same_layout_diagnostic_do_not_gate_or_write(self):
        before, after = self.states()
        after[0][0x02770015].data = (183).to_bytes(4, "little")
        after[0][subject.AP_DIAGNOSTIC].data = b"1234"
        result = subject.preserved(before, after, {})
        self.assertEqual({v["key"] for v in result["diagnostic_changes_not_written"]}, {"02770015", "02cf0b6e"})

    def test_unselected_ap_values_attributes_missing_and_added_fields_still_stop(self):
        for action in ("value", "attr", "missing", "added", "diagnostic-layout"):
            before, after = self.states()
            if action == "value":
                after[0][0x02CF1288].data = b"different"
            elif action == "attr":
                after[0][0x02CF1288].attr = 1
            elif action == "missing":
                del after[0][0x02CF1288]
            elif action == "added":
                after[0][0x02CF9999] = prop(b"new")
            else:
                after[0][subject.AP_DIAGNOSTIC].attr = 0
            with self.subTest(action=action), self.assertRaises(ValueError):
                subject.preserved(before, after, {})

    def test_each_cp_unit_and_its_attributes_remain_protected(self):
        for key in subject.CP_UNITS:
            for action in ("value", "attr", "missing"):
                before, after = self.states()
                if action == "value":
                    after[1][key].data = b"unexpected"
                elif action == "attr":
                    after[1][key].attr = 8
                else:
                    del after[1][key]
                with self.subTest(key=key, action=action), self.assertRaises(ValueError):
                    subject.preserved(before, after, {})

    def test_only_reviewed_ap_bindings_and_cp_targets_may_change(self):
        before, after = self.states()
        after[1][subject.CP_KEYS[0]].data = b"new-look-records"
        subject.preserved(before, after, {(1, subject.CP_KEYS[0]): b"new-look-records"})
        for target in ((0, 0x02770015), (0, subject.AP_DIAGNOSTIC), (0, 0x02CF1288), (1, 0x02A40000)):
            with self.subTest(target=target), self.assertRaises(ValueError):
                subject.preserved(before, after, {target: b"not-a-write-target"})

    def test_actual_private_failed_capture_proves_complete_cp_and_no_saved_ap_change(self):
        root = subject.ROOT / "private/install/20261020-a7cr-fl23-01"
        if not (root / "install-20261020T113452594626Z").is_dir():
            self.skipTest("Actual private failure fixture is not present")
        package = subject.Package(root)
        state = {"phase": "STOPPED_INSPECTION_REQUIRED", "error": subject.REVIEWED_STOP,
                 "attempt": "install-20261020T113452594626Z"}
        report, snapshots = subject.review_cp_stop(package, state)
        self.assertTrue(report["cp_program_complete"])
        self.assertTrue(report["cp_target_units_saved_and_verified"])
        self.assertTrue(report["ap_program_and_bindings_original"])
        self.assertIn("02770015", {v["key"] for v in report["preservation"]["memory"]["diagnostic_changes_not_written"]})
        self.assertFalse(report["preservation"]["flash"]["diagnostic_changes_not_written"])
        for sections in snapshots.values():
            for key in subject.CP_KEYS:
                self.assertEqual(sections[1][key].data, package.units["candidate"][key])

    def test_completion_does_not_accept_another_failure_or_repeated_attempt(self):
        package = fake_package(Path("/synthetic"))
        for state in ({"phase": "PREPARED_NOT_INSTALLED"},
                      {"phase": "STOPPED_INSPECTION_REQUIRED", "error": "timeout", "attempt": "install-original"},
                      {"phase": "STOPPED_INSPECTION_REQUIRED", "error": subject.REVIEWED_STOP, "attempt": "complete-ap-already-attempted"}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                subject.review_cp_stop(package, state)


class GuardTests(unittest.TestCase):
    def test_persistent_protocol_is_limited_to_reviewed_payloads_and_subsystems(self):
        with tempfile.TemporaryDirectory() as folder:
            package = fake_package(Path(folder))
            camera = FakeDevice(package, Mock())
            for key in (0x02A40000, 0x02A40002, 0x02CF1288):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    camera.write_cp(key, "candidate")
                with self.assertRaises(ValueError):
                    camera.write_ap(key, "candidate")
            with self.assertRaises(ValueError):
                camera.write_cp(subject.CP_KEYS[0], "arbitrary")
            for group in (0, 0x00E7, 0x0278):
                with self.assertRaises(ValueError):
                    camera.save_group(group)
            self.assertFalse(camera.operations)

    def test_native_stage_requires_exact_direction_hashes_and_window_count(self):
        package = fake_package(Path("/synthetic"))
        for kind in ("ap_stage", "cp_stage"):
            for mode in (1, 2):
                good = stage_report(package, kind, mode)
                self.assertTrue(subject.decode_stage(good, kind, mode, package)["ok"])
                for changes in ({"16": bytes(64)}, {"17": bytes(64)}, {"4": 2}, {"3": 6}, {"8": -30}):
                    with self.subTest(kind=kind, mode=mode, changes=changes):
                        self.assertFalse(subject.decode_stage(stage_report(package, kind, mode, **changes), kind, mode, package)["ok"])

    def test_wbi_drop_requires_both_writes_closes_original_backend_and_fresh_log(self):
        raw = wbi_report(**{"2": 1, "7": 1, "9": 1, "13": b"0\n", "15": b"*wbi4\n", "16": 1})
        self.assertTrue(subject.decode_wbi_drop(raw)["ok"])
        for change in ({"7": 0}, {"9": 0}, {"8": -5}, {"10": -5}, {"15": b"*wbi3\n"}, {"16": 0}):
            values = {"2": 1, "7": 1, "9": 1, "13": b"0\n", "15": b"*wbi4\n", "16": 1, **change}
            with self.subTest(change=change):
                self.assertFalse(subject.decode_wbi_drop(wbi_report(**values))["ok"])

    def test_native_unknown_result_is_not_retried_or_cleaned(self):
        package = fake_package(Path("/synthetic"))
        camera = TempCamera(TimeoutError("lost native acknowledgement"))
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(TimeoutError):
            subject.invoke(camera, package, "cp_stage", 1, Path(folder), Mock())
        self.assertEqual(camera.invocations, 1)
        self.assertFalse(camera.healthy)
        self.assertFalse(camera.removed)

    def test_install_replay_guard_runs_before_usb_session_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            package = fake_package(Path(folder))
            (package.root / "state.private.json").write_text(json.dumps({"phase": "STOPPED_INSPECTION_REQUIRED"}))
            argv = ["fl23_install.py", "install", "--workspace", str(package.root), "--battery-percent", "100"]
            with (patch.object(subject, "Package", return_value=package), patch.object(subject.os, "geteuid", return_value=0),
                  patch.object(subject.sys, "argv", argv), patch.object(subject, "Session") as session):
                with self.assertRaises(ValueError):
                    subject.main()
                session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
