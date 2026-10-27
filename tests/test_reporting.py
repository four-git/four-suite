import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'src' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Tracking/reporting tests do not exercise flock or real engines. Those require Linux.
if os.name == 'nt':
    with patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
        scanner = load('tracking_fixture', 'four_security.py')
else:
    scanner = load('tracking_fixture', 'four_security.py')
reporting = load('report_fixture', 'reports.py')


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cfg = {'state_db': str(Path(self.temp.name) / 'scans.sqlite3'),
                    'mount': '/mnt/downloads', 'source': '//nas/data', 'roots': ['media'],
                    'retention_days': 30, 'lock_file': str(Path(self.temp.name) / 'scan.lock')}
        self.reports = reporting.Reports(self.cfg, lock_busy=lambda: False)

    def scan(self, **kwargs):
        with patch.object(scanner, '_scan', return_value={'counts': {'CLEAN': 1}, 'visited': 1, 'scan_attempts': 1, 'cached': 0}):
            return scanner.scan(self.cfg, **kwargs)

    def test_tracking_modes_failure_interruption_and_reconciliation(self):
        self.scan()
        self.scan(dry=True)
        self.scan(discover_only=True)
        for exception in (RuntimeError('mount unavailable'), InterruptedError('terminated')):
            with patch.object(scanner, '_scan', side_effect=exception), self.assertRaises(type(exception)):
                scanner.scan(self.cfg)
        runs = self.reports.query('/runs', {})['items']
        self.assertEqual([r['state'] for r in runs[:2]], ['interrupted', 'failed'])
        self.assertEqual(runs[2]['action'], 'discover')
        self.assertTrue(runs[3]['dry_run'])
        self.assertTrue(all(r['duration_seconds'] >= 0 for r in runs))
        status = self.reports.query('/status', {})
        self.assertEqual(status['latest_scan']['state'], 'interrupted')
        self.assertEqual(status['latest_completed_scan']['id'], runs[-1]['id'])
        self.assertFalse(status['stale'])
        db = scanner.database(self.cfg['state_db'])
        db.execute("UPDATE runs SET state='running',ended_at=NULL WHERE id=?", (runs[0]['id'],)); db.commit()
        self.assertEqual(self.reports.query('/status', {})['latest_scan']['state'], 'interrupted')
        busy = reporting.Reports(self.cfg, lock_busy=lambda: True)
        self.assertEqual(busy.query('/status', {})['active_run']['state'], 'running')
        scanner.reconcile_runs(db)
        self.assertEqual(db.execute('SELECT state FROM runs WHERE id=?', (runs[0]['id'],)).fetchone()[0], 'interrupted')
        db.close()

    def test_progress_status_variants_and_error_outcome(self):
        for kind in scanner.STATUSES:
            def work(cfg, dry, target, discover_only, run_id, progress):
                summary = {'counts': {kind: 1}, 'visited': 1, 'scan_attempts': 0, 'cached': 1, 'discovery_truncated': True}
                progress(summary)
                active = reporting.Reports(self.cfg, lock_busy=lambda: True).query('/status', {})['active_run']
                self.assertEqual(active['summary']['counts'], {kind: 1})
                return summary
            with self.subTest(kind=kind), patch.object(scanner, '_scan', side_effect=work):
                result = scanner.scan(self.cfg)
                run = self.reports.query('/runs/' + str(result['run_id']), {})['run']
                self.assertEqual(run['state'], 'failed' if kind == 'SCAN_ERROR' else 'completed')
                self.assertTrue(run['summary']['discovery_truncated'])

    def test_real_walk_counts_caching_limits_and_mount_failure(self):
        root = Path(self.temp.name) / 'media'
        root.mkdir()
        for name in ('clean', 'malware', 'yara', 'partial', 'skipped', 'error'):
            (root / name).write_text(name)
        self.cfg.update(mount=self.temp.name, roots=['media'], stable_seconds=0,
                        max_files_per_run=20, max_runtime_seconds=60)
        results = {
            'clean': ('CLEAN', 'CLEAN'), 'malware': ('MALWARE_DETECTED', 'CLEAN'),
            'yara': ('CLEAN', 'YARA_MATCH'), 'partial': ('SKIPPED_SIZE_LIMIT', 'CLEAN'),
            'skipped': ('SKIPPED_SIZE_LIMIT', 'SKIPPED_SIZE_LIMIT'), 'error': ('SCAN_ERROR', 'CLEAN')}
        def engine(fd, *args):
            name = os.read(fd, 100).decode()
            clam, yara = results[name]
            return {'clam': clam, 'yara': yara}, {k: {'attempted': v != 'SKIPPED_SIZE_LIMIT'} for k, v in [('clam', clam), ('yara', yara)]}
        # Mocked engines allow exercising the walker on Windows; Linux-only
        # O_NOFOLLOW and flock enforcement remain part of host acceptance.
        with patch.object(scanner.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                patch.object(scanner, 'engine_versions', return_value=({}, 'v1')), \
                patch.object(scanner, 'verify_mount'), patch.object(scanner, 'scan_fd', side_effect=engine):
            first = scanner.scan(self.cfg)
            self.assertEqual(first['scan_attempts'], 5)
            self.assertEqual(first['engine_attempts'], {'clam': 4, 'yara': 5})
            self.assertEqual(first['counts']['MALWARE_DETECTED'], 1)
            second = scanner.scan(self.cfg)
            self.assertEqual(second['cached'], 5)
            self.assertEqual(second['scan_attempts'], 0)  # Back off unchanged errors; discovery keeps their evidence.
            self.cfg['max_files_per_run'] = 1
            self.assertTrue(scanner.scan(self.cfg)['discovery_truncated'])
            with patch.object(scanner, 'verify_mount', side_effect=[None, RuntimeError('mount lost')]), self.assertRaises(RuntimeError):
                scanner.scan(self.cfg)
        latest = self.reports.query('/status', {})['latest_scan']
        self.assertEqual(latest['state'], 'failed')
        self.assertEqual(latest['failure_reason'], 'mount lost')
        db = sqlite3.connect(self.cfg['state_db'])
        self.assertTrue(all(row[0] is not None for row in db.execute('SELECT run_id FROM events')))
        db.close()

    def test_paths_evidence_pagination_history_and_read_only(self):
        run_id = self.scan()['run_id']
        db = scanner.database(self.cfg['state_db'])
        path = '/mnt/downloads/media/<script> unusual ü.mkv'
        for i in range(3):
            db.execute('INSERT INTO events(time,path,kind,detail,run_id) VALUES(?,?,?,?,?)',
                       (time.time(), path, 'YARA_MATCH', '{"yara":{"output":"rule /proc/self/fd/4"}}', run_id))
        db.execute('INSERT INTO files(path,status,reason,last_attempt,clam,yara) VALUES(?,?,?,?,?,?)',
                   (path, 'YARA_MATCH', '{"yara":"rule"}', time.time(), 'CLEAN', 'YARA_MATCH'))
        db.commit(); db.close()
        item = self.reports.query('/findings', {})['items'][0]
        self.assertEqual(item['share_path'], '//nas/data/media/<script> unusual ü.mkv')
        self.assertEqual(item['label'], 'Review required')
        self.assertIn('yara', item['evidence'])
        data = self.reports.query('/findings', {'mode': ['history'], 'limit': ['2'], 'offset': ['2']})
        self.assertEqual(data['total'], 3); self.assertEqual(len(data['items']), 1)
        self.assertEqual(self.reports.query('/runs/' + str(run_id), {})['total'], 3)
        with self.assertRaises(ValueError):
            self.reports.query('/runs', {'limit': ['101']})
        before = Path(self.cfg['state_db']).read_bytes()
        self.reports.query('/status', {})
        self.assertEqual(before, Path(self.cfg['state_db']).read_bytes())
        self.assertIsNone(self.reports.query('/scan', {}))

    def test_old_schema_preserved_and_retention(self):
        db = sqlite3.connect(self.cfg['state_db'])
        db.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,time REAL,path TEXT,kind TEXT,detail TEXT)')
        db.execute("INSERT INTO events VALUES(1,?,'/old','MALWARE_DETECTED','old evidence')", (time.time(),))
        db.commit(); db.close()
        self.scan()
        db = scanner.database(self.cfg['state_db'])
        self.assertEqual(db.execute('SELECT detail,run_id FROM events WHERE id=1').fetchone(), ('old evidence', None))
        db.execute('UPDATE runs SET started_at=?,ended_at=?', (time.time()-32*86400, time.time()-32*86400))
        db.commit(); db.close()
        self.assertTrue(self.reports.query('/status', {})['stale'])
        self.assertEqual(self.reports.query('/runs', {})['total'], 0)
        self.scan()
        db = scanner.database(self.cfg['state_db'])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone()[0], 1)
        db.close()


if __name__ == '__main__':
    unittest.main()
