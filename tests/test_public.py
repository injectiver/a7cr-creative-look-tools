import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import a7cr
from tools import photos, upstream


class PublicBoundaryTests(unittest.TestCase):
    def test_doctor_does_not_query_host_identifiers_or_open_usb(self):
        out=io.StringIO()
        with patch.object(upstream,"status",return_value=[]),patch("subprocess.check_output") as process,contextlib.redirect_stdout(out):
            a7cr.main(["doctor"])
        process.assert_not_called()
        report=json.loads(out.getvalue())
        self.assertFalse(report["camera_opened"])
        self.assertFalse(report["serial_numbers_or_hostnames_collected"])
        self.assertNotIn("serial",json.dumps(report).lower().replace("serial_numbers_or_hostnames_collected", ""))

    def test_photo_stems_reject_traversal_duplicates_and_missing_selection(self):
        for stems in ([],["../photo"],["DSC00001","DSC00001"],["/tmp/photo"],["photo.JPG"]):
            with self.subTest(stems=stems),self.assertRaises(ValueError):photos.validate_stems(stems)
        photos.validate_stems(["DSC00001","DSC00002"])

    def test_profile_calibration_is_explicit(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            a7cr.main(["fit-dcp","example.dcp","--slot","1","--name","Example","--output","private/example"])

    def test_pinned_dependencies_have_fixed_commits_and_local_destinations(self):
        rows=upstream.specifications()
        self.assertEqual(len({x["id"] for x in rows}),len(rows))
        self.assertTrue(all(len(x["commit"])==40 for x in rows))
        self.assertTrue(all(x["destination"].startswith("research/") for x in rows))

    def test_identify_uses_descriptor_only_inventory(self):
        with patch.object(a7cr.platform,"system",return_value="Darwin"),patch.object(upstream,"require"),patch.object(a7cr.subprocess,"call",return_value=0) as call:
            self.assertEqual(a7cr.main(["identify"]),0)
        self.assertEqual(call.call_args.args[0][-2:],["identify","--inventory"])

    def test_no_generic_install_command_is_exposed(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):a7cr.main(["install"])


if __name__=="__main__":unittest.main()
