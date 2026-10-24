"""Host-only checks for using a fresh successful backup in preparation."""
import json
from pathlib import Path
import tempfile
import unittest

from prepare_installation import load_completed_capture


class FreshCaptureTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        first, second = Path(temporary.name)/'first', Path(temporary.name)/'second'
        first.mkdir(); second.mkdir()
        manifest = {'schema': 'a7cr-read-only-backup/1', 'phase': 'READ_ONLY_BACKUP_COMPLETE',
                    'firmware_version_user_confirmed': '2.01', 'identity': {'model': 'ILCE-7CR'},
                    'camera_files_or_settings_written': False, 'native_worker_uploaded': False}
        self.save_manifest(first, second, manifest)
        (first/'events.private.json').write_text(json.dumps([
            {'phase': 'service_exit_returned'}, {'phase': 'normal_usb_returned'}, {'phase': 'complete'}]))
        return first, second, manifest

    def save_manifest(self, first, second, manifest):
        for folder in (first, second):
            (folder/'backup.private.json').write_text(json.dumps(manifest))

    def test_accepts_successful_unchanged_backup_without_failure_alias(self):
        first, second, manifest = self.fixture()
        self.assertEqual(load_completed_capture(first, second), manifest)
        self.assertFalse((first/'captured-backup.private.json').exists())

    def test_rejects_wrong_model_firmware_mutation_or_incomplete_capture(self):
        for key, value in [('phase', 'STOPPED'), ('firmware_version_user_confirmed', '2.00'),
                           ('identity', {'model': 'ILCE-7CM2'}),
                           ('camera_files_or_settings_written', True), ('native_worker_uploaded', True)]:
            first, second, manifest = self.fixture()
            manifest[key] = value
            self.save_manifest(first, second, manifest)
            with self.subTest(key=key), self.assertRaises(ValueError):
                load_completed_capture(first, second)

    def test_rejects_disagreeing_manifests(self):
        first, second, _ = self.fixture()
        (second/'backup.private.json').write_text('{}')
        with self.assertRaises(ValueError):
            load_completed_capture(first, second)

    def test_rejects_unknown_service_exit_even_when_files_exist(self):
        first, second, _ = self.fixture()
        (first/'events.private.json').write_text(json.dumps([{'phase': 'stopped_no_retry'}]))
        with self.assertRaises(ValueError):
            load_completed_capture(first, second)


if __name__ == '__main__':
    unittest.main()
