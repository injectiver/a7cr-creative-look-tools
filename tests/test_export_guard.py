from pathlib import Path
import tempfile
import unittest

from tools.audit_publication import audit


class ExportBoundaryTests(unittest.TestCase):
    def test_private_camera_assets_are_not_exported_but_public_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            (root/"README.md").write_text("Research source\n")
            (root/"private").mkdir()
            (root/"private/firmware.bin").write_bytes(b"private camera input")
            self.assertEqual([x["path"] for x in audit(root)["files"]],["README.md"])
            (root/"docs").mkdir()
            (root/"docs/firmware.bin").write_bytes(b"not a release asset")
            with self.assertRaisesRegex(ValueError,"Unexpected publication asset"):audit(root)

    def test_credential_detection_withholds_the_matched_value(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            fake="github_pat_"+"x"*40
            (root/"README.md").write_text(fake)
            with self.assertRaises(ValueError) as error:audit(root)
            self.assertNotIn(fake,str(error.exception))

    def test_known_private_identifier_is_rejected_without_blacklisting_source_signatures(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            (root/"a7cr.py").write_text("signature = bytes.fromhex('00bf')\n")
            self.assertTrue(audit(root)["passed"])
            (root/"README.md").write_text("captured-identifier-for-test")
            with self.assertRaises(ValueError):audit(root,["captured-identifier-for-test"])
