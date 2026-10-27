import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock


loader = importlib.machinery.SourceFileLoader('suite_cli', str(Path(__file__).parents[1] / 'suite'))
spec = importlib.util.spec_from_loader(loader.name, loader)
s = importlib.util.module_from_spec(spec)
loader.exec_module(s)


class SuiteTests(unittest.TestCase):
    def test_publisher_lifecycle_stops_inflight_job_and_respects_enabled_state(self):
        with patch.object(s, 'Path', return_value=Mock(exists=lambda: True)), patch.object(s, 'call') as call:
            s.stop_publisher()
            call.assert_called_once_with(['systemctl', 'stop', 'four-security-publish.timer', 'four-security-publish.service'])
            call.reset_mock()
            with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
                s.start_publisher()
                call.assert_not_called()
            with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                s.start_publisher()
                call.assert_called_once_with(['systemctl', 'start', 'four-security-publish.timer'])

    def test_scan_defers_mount_preflight_to_recording_scanner(self):
        with patch.object(s.sys, 'argv', ['suite', 'scan']), patch.object(s, 'preflight') as preflight, \
                patch.object(s, 'check_native_jobs') as native, patch.object(s, 'compose') as compose:
            self.assertEqual(s.main(), 0)
            preflight.assert_not_called()
            native.assert_called_once()
            compose.assert_called_once_with('exec', '-T', 'scanner', 'python3',
                                           '/opt/four-security/src/container_service.py', 'scan')

    def test_active_native_report_blocks_migration(self):
        def unit_state(args, **kwargs):
            active = args[-1] == 'four-security-report.service' and args[1] == 'is-active'
            return subprocess.CompletedProcess(args, 0 if active else 1)
        with patch.object(s.subprocess, 'run', side_effect=unit_state):
            with self.assertRaisesRegex(RuntimeError, 'report.service'):
                s.check_native_jobs()

    def test_enabled_native_timer_blocks_even_when_inactive(self):
        def unit_state(args, **kwargs):
            enabled = args[-1] == 'four-security-scan.timer' and args[1] == 'is-enabled'
            return subprocess.CompletedProcess(args, 0 if enabled else 1)
        with patch.object(s.subprocess, 'run', side_effect=unit_state):
            with self.assertRaisesRegex(RuntimeError, 'Disable native'):
                s.check_native_jobs()

    def test_backup_stops_ids_and_preserves_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env').write_text('SUITE_IMAGE=sha256:test\n')
            (root / 'deployment-manifest.json').write_text('{}')
            with patch.object(s, 'ROOT', root), patch.object(s, 'BACKUPS', root / 'backups'), \
                    patch.object(s, 'PATHS', ()), patch.object(s, 'compose') as compose, \
                    patch.object(s, 'check_native_jobs'), patch.object(s, 'stop_publisher'):
                backup = s.backup()
                compose.assert_called_once_with('--profile', 'ids', 'stop')
                self.assertEqual((backup / 'suite.env').read_text(), 'SUITE_IMAGE=sha256:test\n')

    def test_copy_uses_archive_semantics_without_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'nested' / 'state'
            with patch.object(s, 'call') as call:
                s.copy_tree(Path('/original'), target)
            call.assert_called_once_with(['cp', '-a', '--', str(Path('/original')), str(target)], timeout=None)
            self.assertTrue(target.parent.is_dir())

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0
                         and shutil.which('cp'), 'Numeric ownership round trip requires Linux root and cp')
    def test_state_ownership_survives_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'state'
            original.mkdir(mode=0o750)
            db = original / 'scans.sqlite3'
            db.write_bytes(b'disposable fixture')
            db.chmod(0o640)
            os.chown(original, 997, 983)
            os.chown(db, 997, 983)
            (original / 'db-link').symlink_to('scans.sqlite3')
            os.lchown(original / 'db-link', 997, 983)
            saved = root / 'snapshot' / 'state'
            s.copy_tree(original, saved)
            shutil.rmtree(original)
            s.copy_tree(saved, original)
            for item in (original, original / 'scans.sqlite3', original / 'db-link'):
                self.assertEqual((item.lstat().st_uid, item.lstat().st_gid), (997, 983))
            self.assertEqual(db.stat().st_mode & 0o777, 0o640)
            self.assertEqual(db.read_bytes(), b'disposable fixture')
            self.assertEqual(os.readlink(original / 'db-link'), 'scans.sqlite3')


if __name__ == '__main__':
    unittest.main()
