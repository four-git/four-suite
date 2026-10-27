import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import os

if os.name != 'posix':
    raise unittest.SkipTest('Scanner engine/file-descriptor tests require Linux; reporting tests run on Windows')

spec = importlib.util.spec_from_file_location('scanner', Path(__file__).parents[1] / 'src/four_security.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class ScannerTests(unittest.TestCase):
    def test_engine_results_are_distinct(self):
        self.assertEqual(s.interpret('clam', 1, 'x: Eicar-Test-Signature FOUND'), 'MALWARE_DETECTED')
        self.assertEqual(s.interpret('clam', 1, 'x: Heuristics.Limits.Exceeded.MaxFileSize FOUND'), 'SKIPPED_SIZE_LIMIT')
        self.assertEqual(s.interpret('clam', 1, 'x: Heuristics.Limits.Exceeded.MaxScanTime FOUND'), 'SCAN_ERROR')
        self.assertEqual(s.interpret('clam', 2, 'permission denied'), 'SCAN_ERROR')
        self.assertEqual(s.interpret('clam', 0, ''), 'CLEAN')
        self.assertEqual(s.interpret('clam', 0, 'WARNING: unreadable'), 'SCAN_ERROR')
        self.assertEqual(s.interpret('yara', 0, 'benign_rule x'), 'YARA_MATCH')
        self.assertEqual(s.interpret('yara', 1, 'syntax error'), 'SCAN_ERROR')
        self.assertEqual(s.combine('CLEAN', 'SKIPPED_SIZE_LIMIT'), 'PARTIALLY_SCANNED')
        self.assertEqual(s.combine('SKIPPED_SIZE_LIMIT', 'SKIPPED_SIZE_LIMIT'), 'SKIPPED_SIZE_LIMIT')
        self.assertEqual(s.combine('MALWARE_DETECTED', 'SCAN_ERROR'), 'MALWARE_DETECTED')

    def test_mount_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'mount': d, 'source': '//nas/data', 'expected_dirs': []}
            bad = {'filesystems': [{'source': '/dev/root', 'target': d, 'fstype': 'ext4', 'options': 'rw'}]}
            with patch.object(s, 'command', return_value=type('R', (), {'returncode': 0, 'stdout': json.dumps(bad)})()):
                with self.assertRaises(RuntimeError):
                    s.verify_mount(cfg)
            good = {'filesystems': [{'source': '//nas/data', 'target': d, 'fstype': 'cifs', 'options': 'ro,nodev'}]}
            with patch.object(s, 'command', return_value=type('R', (), {'returncode': 0, 'stdout': json.dumps(good)})()):
                self.assertEqual(s.verify_mount(cfg)['fstype'], 'cifs')

    def test_mount_accepts_autofs_with_one_read_only_cifs(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'mount': d, 'source': '//nas/data', 'expected_dirs': []}
            autofs = {'source': 'systemd-1', 'target': d, 'fstype': 'autofs', 'options': 'rw,relatime'}
            cifs = {'source': '//nas/data', 'target': d, 'fstype': 'cifs', 'options': 'ro,nosuid,nodev'}
            for rows in ([autofs, cifs], [cifs, autofs]):
                with self.subTest(rows=rows):
                    result = type('R', (), {'returncode': 0, 'stdout': json.dumps({'filesystems': rows})})()
                    with patch.object(s, 'command', return_value=result):
                        self.assertEqual(s.verify_mount(cfg), cifs)

    def test_mount_autofs_wrapper_does_not_hide_unsafe_mounts(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'mount': d, 'source': '//nas/data', 'expected_dirs': []}
            autofs = {'source': 'systemd-1', 'target': d, 'fstype': 'autofs', 'options': 'rw'}
            cifs = {'source': '//nas/data', 'target': d, 'fstype': 'cifs', 'options': 'ro'}
            cases = {
                'autofs only': [autofs],
                'missing': [],
                'writable': [autofs, dict(cifs, options='rw')],
                'conflicting flags': [autofs, dict(cifs, options='ro,rw')],
                'wrong source': [autofs, dict(cifs, source='//other/data')],
                'wrong target': [autofs, dict(cifs, target=d + '/other')],
                'local filesystem': [autofs, dict(cifs, fstype='ext4')],
                'multiple backing mounts': [autofs, cifs, dict(cifs)],
                'unrelated wrapper': [dict(autofs, target=d + '/other'), cifs],
                'multiple wrappers': [autofs, dict(autofs), cifs],
            }
            for name, rows in cases.items():
                with self.subTest(name=name):
                    result = type('R', (), {'returncode': 0, 'stdout': json.dumps({'filesystems': rows})})()
                    with patch.object(s, 'command', return_value=result):
                        with self.assertRaises(RuntimeError):
                            s.verify_mount(cfg)

    def test_mount_opens_automount_before_inspection(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'mount': d, 'source': '//nas/data', 'expected_dirs': []}
            activated = False

            def activate(*args):
                nonlocal activated
                activated = True
                from contextlib import nullcontext
                return nullcontext()

            def inspect(*args):
                row = {'source': '//nas/data' if activated else 'systemd-1',
                       'target': d, 'fstype': 'cifs' if activated else 'autofs',
                       'options': 'ro,nodev'}
                return type('R', (), {'returncode': 0, 'stdout': json.dumps({'filesystems': [row]})})()

            with patch.object(s.os, 'scandir', side_effect=activate), patch.object(s, 'command', side_effect=inspect):
                self.assertEqual(s.verify_mount(cfg)['fstype'], 'cifs')

    def test_pending_scan_cache_and_change(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'media').mkdir()
            file = base / 'media/test.txt'
            file.write_text('safe')
            cfg = {'mount': d, 'source': '//nas/data', 'roots': ['media'], 'state_db': str(base / 'state.db'),
                   'max_runtime_seconds': 10, 'max_files_per_run': 20, 'stable_seconds': 0, 'retention_days': 30}
            with patch.object(s, 'verify_mount'), patch.object(s, 'engine_versions', return_value=({}, 'v1')), \
                    patch.object(s, 'scan_fd', return_value=({'clam': 'CLEAN', 'yara': 'CLEAN'}, {})) as engine:
                cfg['stable_seconds'] = 100
                self.assertEqual(s.scan(cfg)['counts'], {'PENDING': 1})
                cfg['stable_seconds'] = 0
                self.assertEqual(s.scan(cfg)['counts'], {'CLEAN': 1})
                self.assertEqual(engine.call_count, 1)
                self.assertEqual(s.scan(cfg)['cached'], 1)
                self.assertEqual(engine.call_count, 1)
                file.write_text('changed file')
                self.assertEqual(s.scan(cfg)['scan_attempts'], 1)
                self.assertEqual(engine.call_count, 2)
                db = sqlite3.connect(cfg['state_db'])
                self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE kind='FILE_CHANGED'").fetchone()[0], 1)
                with self.assertRaises(RuntimeError):
                    s.scan(cfg, target=str(base / 'state.db'))

    def test_limits_and_timeouts(self):
        cfg = {'clam_max_bytes': 200, 'clam_scan_bytes': 400, 'yara_max_bytes': 50, 'engine_timeout': 1, 'rules': 'test.yar'}
        result, _ = s.scan_fd(999, 201, cfg, time.monotonic() + 10)
        self.assertEqual(s.combine(result['clam'], result['yara']), 'SKIPPED_SIZE_LIMIT')
        with patch.object(s, 'command', side_effect=s.subprocess.TimeoutExpired('scanner', 1)):
            result, _ = s.scan_fd(999, 10, cfg, time.monotonic() + 10)
            self.assertEqual(s.combine(result['clam'], result['yara']), 'SCAN_ERROR')

    def test_oldest_attempt_first_after_signature_update(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'media').mkdir()
            for name in ('a', 'z'):
                (base / 'media' / name).write_text(name)
            cfg = {'mount': d, 'source': '//nas/data', 'roots': ['media'], 'state_db': str(base / 'state.db'),
                   'max_runtime_seconds': 10, 'max_files_per_run': 20, 'stable_seconds': 0, 'retention_days': 30}
            order = []
            def engine(fd, *args):
                order.append(s.os.pread(fd, 10, 0).decode())
                return {'clam': 'CLEAN', 'yara': 'CLEAN'}, {}
            with patch.object(s, 'verify_mount'), patch.object(s, 'engine_versions', return_value=({}, 'v1')), patch.object(s, 'scan_fd', side_effect=engine):
                s.scan(cfg)
            db = sqlite3.connect(cfg['state_db'])
            db.execute('UPDATE files SET last_attempt=100 WHERE path=?', (str(base / 'media/a'),))
            db.execute('UPDATE files SET last_attempt=1 WHERE path=?', (str(base / 'media/z'),))
            db.commit()
            db.close()
            order.clear()
            with patch.object(s, 'verify_mount'), patch.object(s, 'engine_versions', return_value=({}, 'v2')), patch.object(s, 'scan_fd', side_effect=engine):
                s.scan(cfg)
            self.assertEqual(order, ['z', 'a'])

    def test_file_changed_during_scan_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'media').mkdir()
            file = base / 'media/test.txt'
            file.write_text('safe')
            (base / 'media/link').symlink_to(file)
            cfg = {'mount': d, 'source': '//nas/data', 'roots': ['media'], 'state_db': str(base / 'state.db'),
                   'max_runtime_seconds': 10, 'max_files_per_run': 20, 'stable_seconds': 0, 'retention_days': 30}
            def changing(*args):
                file.write_text('modified during scan')
                return {'clam': 'CLEAN', 'yara': 'CLEAN'}, {}
            with patch.object(s, 'verify_mount'), patch.object(s, 'engine_versions', return_value=({}, 'v1')), patch.object(s, 'scan_fd', side_effect=changing):
                counts = s.scan(cfg)['counts']
                self.assertEqual(counts['PENDING'], 1)
                self.assertEqual(counts['SKIPPED_POLICY'], 1)

    def test_signature_change_during_scan_is_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'media').mkdir()
            (base / 'media/test.txt').write_text('safe')
            cfg = {'mount': d, 'source': '//nas/data', 'roots': ['media'], 'state_db': str(base / 'state.db'),
                   'max_runtime_seconds': 10, 'max_files_per_run': 20, 'stable_seconds': 0, 'retention_days': 30}
            with patch.object(s, 'verify_mount'), patch.object(s, 'engine_versions', side_effect=[({}, 'v1'), ({}, 'v2')]), \
                    patch.object(s, 'scan_fd', return_value=({'clam': 'CLEAN', 'yara': 'CLEAN'}, {})):
                self.assertEqual(s.scan(cfg)['counts'], {'PENDING': 1})


if __name__ == '__main__':
    unittest.main()
