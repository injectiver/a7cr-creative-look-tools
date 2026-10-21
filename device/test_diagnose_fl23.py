"""Boundary and ABI checks for temporary read-only loaded-state diagnosis."""
import ast
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import diagnose_fl23 as subject


def fixtures(live="candidate", status=0):
    old, new = bytes(256), bytearray(256)
    spans = []
    for index in range(8):
        offset = index*4
        new[offset:offset+2] = bytes([index+1, 0])
        spans.append({"name": f"span{index}", "offset": offset, "bytes": 2})
    package = SimpleNamespace(programs={"original": {"AP": old}, "candidate": {"AP": bytes(new)}})
    runtime = bytearray(2344)
    struct.pack_into("<8sII3qQII", runtime, 0, b"A7CRR001", 1, 8, status, 0, 123, 0x50000000, 0, 0)
    for index, span in enumerate(spans):
        offset = span["offset"]
        runtime[56+index*256:56+index*256+2] = package.programs[live]["AP"][offset:offset+2]
        runtime[56+index*256+128:56+index*256+130] = package.programs["candidate"]["AP"][offset:offset+2]
    struct.pack_into("<16s32s128s64s", runtime, 2104, b"2\n", b"*wbi4\n", b"3.00 12.00\n",
                     b"12345678-1234-1234-1234-123456789abc\n")
    probe = struct.pack("<8sII4qQ4I", b"A7PRB001", 1, 0, 0, 0, 123, 0, 0x50000000, 1, 0, 0, 0)+b"\n"
    return package, spans, bytes(runtime), probe


class TemporaryCamera:
    def __init__(self, runtime, probe, failure=None):
        self.files = {}
        self.runtime, self.probe, self.failure = runtime, probe, failure
        self.healthy = True
        self.writes, self.removed = [], []

    def read_temp(self, name, optional=False):
        return self.files.get(name)

    def check_preload(self):
        pass

    def write_temp(self, name, raw, expected):
        if raw != expected[name]:
            raise AssertionError("Unreviewed temporary contents")
        self.writes.append(name)
        self.files[name] = raw
        if name == "libJit.so":
            if self.failure:
                raise self.failure
            del self.files[name]
            self.files["a7cr.diag.probe.result"] = self.probe
            self.files["a7cr.diag.runtime.result"] = self.runtime

    def remove_temp(self, name, expected):
        self.removed.append(name)
        if name in self.files:
            if self.files[name] != expected[name]:
                raise AssertionError("Unowned temporary contents")
            del self.files[name]


class DiagnosticTests(unittest.TestCase):
    def test_new_and_stale_loaded_spans_are_distinguished_from_disk(self):
        for direction in ("candidate", "original"):
            package, spans, runtime, probe = fixtures(direction)
            result = subject.decode_runtime(runtime, spans, package)
            self.assertTrue(result["ok"])
            self.assertEqual(result["all_loaded_ap_spans_match_candidate"], direction == "candidate")
            self.assertTrue(all(row["loaded_state"] == direction and row["disk_state"] == "candidate" for row in result["spans"]))
            self.assertFalse(result["running_cp_memory_read"])
            self.assertEqual(subject.decode_probe(probe)["pid"], result["pid"])

    def test_malformed_runtime_abi_or_privilege_is_rejected(self):
        package, spans, raw, _ = fixtures()
        for at, replacement in ((0, b"BADMAGIC"), (8, struct.pack("<I", 2)), (12, struct.pack("<I", 6)),
                                (24, struct.pack("<q", 501)), (48, struct.pack("<I", 1))):
            bad = bytearray(raw); bad[at:at+len(replacement)] = replacement
            with self.subTest(at=at), self.assertRaises(ValueError):
                subject.decode_runtime(bad, spans, package)
        with self.assertRaises(ValueError):
            subject.decode_runtime(raw[:-1], spans, package)

    def test_native_read_error_is_not_misreported_as_loaded_success(self):
        package, spans, raw, _ = fixtures(status=-14)
        result = subject.decode_runtime(raw, spans, package)
        self.assertFalse(result["ok"])
        self.assertFalse(result["all_loaded_ap_spans_match_candidate"])
        self.assertTrue(all(row["loaded_state"] == "read_failed" for row in result["spans"]))

    def test_one_invocation_then_only_owned_temp_cleanup(self):
        package, spans, raw, probe = fixtures()
        camera = TemporaryCamera(raw, probe)
        with tempfile.TemporaryDirectory() as folder:
            result = subject.invoke(camera, b"reviewed-readonly-worker", spans, package, Path(folder), Mock())
        self.assertTrue(result["ok"])
        self.assertEqual(camera.writes, ["a7cr.diag-staged.so", "libJit.so"])
        self.assertFalse(camera.files)

    def test_unknown_invocation_leaves_evidence_and_does_not_retry_or_cleanup(self):
        package, spans, raw, probe = fixtures()
        camera = TemporaryCamera(raw, probe, TimeoutError("unknown result"))
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(TimeoutError):
            subject.invoke(camera, b"worker", spans, package, Path(folder), Mock())
        self.assertFalse(camera.healthy)
        self.assertEqual(camera.writes.count("libJit.so"), 1)
        self.assertFalse(camera.removed)

    def test_existing_temp_files_stop_before_invocation(self):
        package, spans, raw, probe = fixtures()
        for name in subject.NAMES:
            camera = TemporaryCamera(raw, probe)
            camera.files[name] = b"previous-evidence"
            with tempfile.TemporaryDirectory() as folder, self.subTest(name=name), self.assertRaises(ValueError):
                subject.invoke(camera, b"worker", spans, package, Path(folder), Mock())
            self.assertFalse(camera.writes)

    def test_diagnostic_session_has_no_persistent_write_methods_or_unowned_paths(self):
        camera = subject.DiagnosticSession(None, Mock())
        camera.channel = SimpleNamespace(sendSenserPacket=Mock())
        for method in ("write_cp", "write_ap", "save_group"):
            self.assertFalse(hasattr(camera, method))
        for name in ("../appFw.so", "/sys/power/image_drop", "unknown-result"):
            with self.assertRaises(ValueError):
                camera.select_temp(name)
        camera.channel.sendSenserPacket.assert_not_called()
        tree = ast.parse(Path(subject.__file__).read_text())
        methods = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(methods & {"write_cp", "write_ap", "save_group", "writeBackup", "saveBackup", "writeMemory", "setBackupPresetData"})


if __name__ == "__main__":
    unittest.main()
