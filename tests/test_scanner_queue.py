"""Regression checks for discovery, resumable work, and active-content policy."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

if os.name != 'posix':
    raise unittest.SkipTest('Linux descriptor scanner tests')
spec = importlib.util.spec_from_file_location('queue_scanner', Path(__file__).parents[1] / 'src/four_security.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'media').mkdir()
        self.cfg = dict(mount=str(self.root), source='//nas/data', roots=['media'],
                        state_db=str(self.root / 'state.db'), max_runtime_seconds=10,
                        max_files_per_run=20, stable_seconds=0, retention_days=30)
        self.mount = patch.object(s, 'verify_mount').start()
        self.versions = patch.object(s, 'engine_versions', return_value=({}, 'v1')).start()
        self.engine = patch.object(s, 'scan_fd', return_value=({'clam': 'CLEAN', 'yara': 'CLEAN'}, {})).start()

    def tearDown(self):
        patch.stopall()
        self.temp.cleanup()

    def file(self, name, data=b'safe'):
        p = self.root / 'media' / name
        p.write_bytes(data)
        return p

    def row(self, p):
        with sqlite3.connect(self.cfg['state_db']) as db:
            return db.execute('SELECT * FROM files WHERE path=?', (str(p),)).fetchone()

    def test_discovery_preserves_error_evidence_attempt_and_stale_fingerprint(self):
        p = self.file('a')
        self.engine.return_value = ({'clam': 'SCAN_ERROR', 'yara': 'CLEAN'}, {'clam': {'attempted': True, 'reason': 'timeout'}})
        s.scan(self.cfg)
        before = self.row(p)
        self.versions.return_value = ({}, 'v2')
        result = s.scan(self.cfg, discover_only=True)
        self.assertEqual(before, self.row(p))
        self.assertEqual(result['scan_attempts'], 0)
        with sqlite3.connect(self.cfg['state_db']) as db:
            self.assertEqual(db.execute('SELECT state FROM runs ORDER BY id DESC LIMIT 1').fetchone()[0], 'completed')

    def test_discovery_preserves_clean_result_when_signatures_change(self):
        p = self.file('a')
        s.scan(self.cfg)
        before = self.row(p)
        self.versions.return_value = ({}, 'v2')
        s.scan(self.cfg, discover_only=True)
        self.assertEqual(before, self.row(p))

    def test_changed_file_becomes_pending_without_erasing_last_attempt(self):
        p = self.file('a')
        s.scan(self.cfg)
        attempt = self.row(p)[9]
        p.write_bytes(b'new contents')
        s.scan(self.cfg, discover_only=True)
        self.assertEqual(self.row(p)[6], 'PENDING')
        self.assertEqual(self.row(p)[9], attempt)

    def test_queue_continuation_moves_to_unattempted_file(self):
        self.file('a')
        self.file('z')
        self.cfg['max_files_per_run'] = 1
        self.assertTrue(s.scan(self.cfg)['work_remaining'])
        order = []
        self.engine.side_effect = lambda fd, *args: (order.append(os.pread(fd, 4, 0)) or ({'clam': 'CLEAN', 'yara': 'CLEAN'}, {}))
        self.assertFalse(s.scan(self.cfg)['work_remaining'])
        self.assertEqual(len(order), 1)
        self.assertEqual(self.engine.call_count, 2)

    def test_retry_backoff_does_not_reexecute_error_file(self):
        self.file('a')
        self.engine.return_value = ({'clam': 'SCAN_ERROR', 'yara': 'CLEAN'}, {})
        s.scan(self.cfg)
        s.scan(self.cfg, discover_only=True)
        self.assertFalse(s.scan(self.cfg)['work_remaining'])
        self.assertEqual(self.engine.call_count, 1)

    def test_disguised_pe_is_flagged_without_execution(self):
        data = bytearray(512)
        data[:2] = b'MZ'
        data[60:64] = (128).to_bytes(4, 'little')
        data[128:132] = b'PE\0\0'
        p = self.file('episode.mp4', data)
        self.cfg['media_policy'] = True
        result = s.scan(self.cfg)
        self.assertEqual(result['counts'], {'POLICY_VIOLATION': 1})
        self.assertEqual(result['scan_attempts'], 0)
        self.engine.assert_not_called()
        self.assertEqual(p.read_bytes(), data)

    def test_batch_deadline_does_not_cut_off_admitted_file(self):
        self.file('a')
        self.cfg['engine_timeout'] = 20
        deadlines = []
        self.engine.side_effect = lambda fd, size, cfg, deadline: (deadlines.append(deadline-time.monotonic()) or ({'clam': 'CLEAN', 'yara': 'CLEAN'}, {}))
        s.scan(self.cfg)
        self.assertGreater(deadlines[0], 40)

    def test_zero_yara_limit_means_full_file_not_skip(self):
        patch.stopall()
        cfg = dict(clam_max_bytes=1900000000, clam_scan_bytes=1900000000,
                   yara_max_bytes=0, engine_timeout=1200, rules='rules.yar')
        result = type('Result', (), dict(returncode=0, stdout='', stderr=''))()
        with patch.object(s, 'command', return_value=result) as command:
            engines, evidence = s.scan_fd(999, 25_000_000_000, cfg, time.monotonic()+1300)
        self.assertEqual(engines, {'clam': 'SKIPPED_SIZE_LIMIT', 'yara': 'CLEAN'})
        self.assertEqual(command.call_args.args[0][0], 'yara')

    def test_daemon_fdpass_path_is_used(self):
        patch.stopall()
        cfg = dict(clam_max_bytes=1900000000, clam_scan_bytes=1900000000, yara_max_bytes=0,
                   engine_timeout=1200, rules='rules.yar', clam_mode='daemon')
        result = type('Result', (), dict(returncode=0, stdout='', stderr=''))()
        with patch.object(s, 'command', return_value=result) as command:
            s.scan_fd(99, 100, cfg, time.monotonic()+1300)
        self.assertEqual(command.call_args_list[0].args[0][0], 'clamdscan')
        self.assertIn('--fdpass', command.call_args_list[0].args[0])

    def test_large_file_yara_budget_scales_without_extending_clam(self):
        cfg = {'engine_timeout': 1200, 'yara_seconds_per_gib': 120}
        self.assertEqual(s.engine_budget('yara', 90 * 1073741824, cfg), 10800)
        self.assertEqual(s.engine_budget('yara', 100, cfg), 1200)
        self.assertEqual(s.engine_budget('clam', 90 * 1073741824, cfg), 1200)

    def test_yara_x_uses_inherited_file_and_size_scaled_timeout(self):
        patch.stopall()
        cfg = dict(clam_max_bytes=1900000000, clam_scan_bytes=1900000000,
                   yara_max_bytes=0, engine_timeout=1200, rules='rules.yar', yara_mode='yara-x')
        result = type('Result', (), dict(returncode=0, stdout='', stderr=''))()
        with patch.object(s, 'command', return_value=result) as command:
            engines, _ = s.scan_fd(99, 19 * 1073741824, cfg, time.monotonic()+2400)
        self.assertEqual(engines['yara'], 'CLEAN')
        self.assertIn('2280', command.call_args.args[0])
        self.assertEqual(command.call_args.args[0][-1], '/proc/self/fd/99')
        self.assertEqual(command.call_args.kwargs['pass_fds'], (99,))
