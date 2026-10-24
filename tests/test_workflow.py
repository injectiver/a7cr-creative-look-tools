"""Agent interface isolation, explicit actions and private project boundaries."""
import contextlib
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock

import a7cr
from tools import workflow,project_paths


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'camera project'

    def init(self):return workflow.initialize(self.root,'2.01')

    def test_init_and_status_never_start_backend_or_usb(self):
        with patch.object(workflow.subprocess,'run') as backend:
            self.init();result=workflow.status(self.root)
        backend.assert_not_called();self.assertFalse(result['camera_opened'])
        self.assertEqual(result['jobs']['portrait']['recorded_phase'],'NOT_PREPARED')

    def test_external_project_and_paths_with_spaces(self):
        self.init()
        with patch.dict(os.environ,{project_paths.ENV:str(self.root)}):
            self.assertEqual(project_paths.runtime_root(),self.root.resolve())
        argv=workflow.command(self.root,'portrait','verify')
        self.assertIn(str(self.root/'private/portrait-slots-install/portrait'),argv)

    def test_existing_project_never_overwritten(self):
        self.init();(self.root/'private/keep.txt').write_text('keep')
        with self.assertRaises(ValueError):self.init()
        self.assertEqual((self.root/'private/keep.txt').read_text(),'keep')

    def test_changed_executable_link_rejected(self):
        self.init();(self.root/'device').unlink();(self.root/'device').mkdir()
        with self.assertRaisesRegex(ValueError,'link changed'):workflow.status(self.root)

    def test_private_directory_escape_rejected(self):
        self.init();(self.root/'private').rmdir();(self.root/'private').symlink_to(Path(self.temp.name))
        with self.assertRaisesRegex(ValueError,'Private project data'):workflow.status(self.root)

    def test_wrong_model_firmware_and_schema_rejected(self):
        self.init();path=self.root/'project.json';saved=json.loads(path.read_text())
        for key,value in (('model','ILCE-7CM2'),('firmware','2.00'),('schema','unknown')):
            path.write_text(json.dumps({**saved,key:value}))
            with self.subTest(key=key),self.assertRaises(ValueError):workflow.status(self.root)

    def test_install_and_restore_reject_low_or_inferred_power(self):
        self.init()
        for operation in ('install','restore'):
            for battery in (None,50,74,101,True):
                with self.subTest(operation=operation,battery=battery),patch.object(workflow.subprocess,'run') as backend:
                    with self.assertRaises(ValueError):workflow.run(self.root,'portrait',operation,battery=battery)
                    backend.assert_not_called()

    def test_install_explicit_battery_argument(self):
        self.init();argv=workflow.command(self.root,'portrait','install',battery=85)
        self.assertEqual(argv[-2:],['--battery-percent','85'])
        self.assertEqual(argv[-4:-2],['--command','install'])

    def test_verify_never_requests_an_install(self):
        self.init();argv=workflow.command(self.root,'single','verify')
        self.assertEqual(argv[-2:],['--command','verify']);self.assertNotIn('--battery-percent',argv)

    def test_prepare_requires_explicit_owned_checkpoint(self):
        self.init()
        for checkpoint in (None,Path(self.temp.name)/'other.json'):
            with self.subTest(checkpoint=checkpoint),self.assertRaises(ValueError):
                workflow.command(self.root,'portrait','prepare',checkpoint=checkpoint)

    def test_finalize_and_validate_have_distinct_actions(self):
        self.init();a=workflow.command(self.root,'portrait','finalize');b=workflow.command(self.root,'portrait','validate')
        self.assertIn('--finalize',a);self.assertNotIn('--finalize',b)

    def test_unknown_operation_and_stage_cannot_execute_code(self):
        for stage,operation in (('../other','verify'),('portrait','eval'),('portrait','; rm anything')):
            with self.assertRaises(ValueError):workflow.command(self.root,stage,operation)

    def test_exit_review_cannot_reinstall(self):
        self.init();a=workflow.command(self.root,'portrait','review-exit')
        self.assertIn('--verify',a);self.assertNotIn('install',a)
        with self.assertRaises(ValueError):workflow.command(self.root,'single','review-exit')

    def test_nonroot_camera_command_stops_before_backend(self):
        self.init()
        with patch.object(workflow.os,'geteuid',return_value=501),patch.object(workflow.sys,'platform','darwin'),patch.object(workflow.subprocess,'run') as backend:
            with self.assertRaises(PermissionError):workflow.run(self.root,'portrait','verify')
        backend.assert_not_called()

    def test_offline_failure_is_logged_once_without_retry(self):
        self.init()
        with patch.object(workflow.subprocess,'run',return_value=Mock(returncode=2)) as backend:
            result=workflow.run(self.root,'portrait','validate')
        self.assertEqual(backend.call_count,1);self.assertFalse(result['ok']);self.assertFalse(result['automatic_retry'])
        self.assertFalse(result['camera_action_requested']);self.assertTrue(Path(result['log']).is_file())

    def test_project_cli_uses_json_on_error(self):
        self.init();out=io.StringIO()
        with contextlib.redirect_stdout(out):
            code=a7cr.main(['project','run','--project',str(self.root),'--stage','portrait','--operation','install','--battery-percent','20'])
        self.assertEqual(code,2);self.assertFalse(json.loads(out.getvalue())['ok'])

    def test_build_assets_is_an_offline_fixed_entry_point(self):
        self.init();argv=workflow.command(self.root,'single','build-assets')
        self.assertEqual(argv[-2:],['--stage','single'])
        self.assertTrue(argv[1].endswith('/offline/build_project_assets.py'))
        self.assertNotIn('build-assets',workflow.USB_OPERATIONS)

    def test_profiles_require_explicit_model_acceptance(self):
        self.init()
        with self.assertRaises(ValueError):workflow.fit_profiles(self.root,{})
        self.assertFalse((self.root/'private/single-slot-input').exists())

    def test_unknown_profile_is_rejected_before_copying_or_fitting(self):
        self.init();source=Path(self.temp.name)/'different.dcp';source.write_bytes(b'not the reviewed original')
        with patch.object(workflow.subprocess,'run') as backend,self.assertRaisesRegex(ValueError,'profile differs'):
            workflow.fit_profiles(self.root,{1:source,2:source,3:source},use_upstream_model=True)
        backend.assert_not_called();self.assertFalse((self.root/'private/single-slot-input').exists())

    @unittest.skipIf(sys.platform=='win32','POSIX host lock')
    def test_host_lock_blocks_a_second_project_and_releases(self):
        lock=Path(self.temp.name)/'usb.lock'
        with patch.object(workflow,'_lock_path',return_value=str(lock)):
            with workflow.host_usb_lock():
                with self.assertRaises(BlockingIOError):
                    with workflow.host_usb_lock():self.fail('second owner entered')
            with workflow.host_usb_lock():pass


if __name__=='__main__':unittest.main()
