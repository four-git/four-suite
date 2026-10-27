import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
import shutil
import subprocess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))
import publish_reports as publisher
from reports import Reports


class PublishingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = {'state_db': str(self.root / 'scans.sqlite3'), 'mount': '/mnt/four-security/downloads',
                    'source': '//nas/data', 'lock_file': str(self.root / 'scan.lock'), 'retention_days': 30}
        self.db = sqlite3.connect(self.cfg['state_db'])
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE files(path TEXT PRIMARY KEY,status TEXT,reason TEXT,last_attempt REAL,stable_since REAL,clam TEXT,yara TEXT);
            CREATE TABLE events(id INTEGER PRIMARY KEY,time REAL,path TEXT,kind TEXT,detail TEXT,run_id INTEGER);
            CREATE TABLE runs(id INTEGER PRIMARY KEY,action TEXT,dry_run INTEGER,scope TEXT,started_at REAL,ended_at REAL,
                updated_at REAL,duration_seconds REAL,state TEXT,failure_reason TEXT,summary TEXT);
        ''')

    def add_run(self, action='scan', dry=0, state='completed', stamp=None):
        now = stamp or time.time()
        summary = json.dumps({'visited': 8, 'scan_attempts': 3, 'cached': 5, 'counts': {'CLEAN': 8}})
        self.db.execute('INSERT INTO runs VALUES(NULL,?,?,?,?,?,?,?,?,?,?)',
                        (action, dry, '[]', now-12, now if state != 'running' else None, now, 12, state, None, summary))
        self.db.commit()

    def reports(self, busy=False):
        return Reports(self.cfg, lock_busy=lambda: busy)

    def test_empty_database_and_unavailable_database_are_distinct(self):
        snap = self.reports().snapshot()
        self.assertIsNone(snap['latest_scan'])
        self.assertEqual(snap['retained_scan_count'], 0)
        self.assertEqual(snap['findings'], [])
        self.cfg['state_db'] = str(self.root / 'missing.sqlite3')
        with self.assertRaises(sqlite3.Error):
            self.reports().snapshot()
        self.assertFalse(Path(self.cfg['state_db']).exists())

    def test_snapshot_counts_modes_retention_progress_and_no_mutations(self):
        self.add_run(stamp=time.time()-32*86400)
        self.add_run()
        self.add_run('discover')
        self.add_run(dry=1)
        self.add_run(state='running')
        before = Path(self.cfg['state_db']).read_bytes()
        snap = self.reports(True).snapshot()
        self.assertEqual(snap['retained_scan_count'], 2)
        self.assertEqual(snap['latest_scan']['state'], 'running')
        self.assertEqual(snap['latest_completed_scan']['summary']['scan_attempts'], 3)
        self.assertEqual(snap['active_run']['state'], 'running')
        self.assertEqual(len(snap['recent_runs']), 2)
        interrupted = self.reports().snapshot()
        self.assertIsNone(interrupted['active_run'])
        self.assertEqual(interrupted['latest_scan']['state'], 'interrupted')
        self.assertEqual(before, Path(self.cfg['state_db']).read_bytes())

    def test_all_findings_and_absolute_share_paths_and_changed_files(self):
        now = time.time()
        for i in range(125):
            self.db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?)',
                            (f"{self.cfg['mount']}/media/<tag> ü{i}.mkv", 'YARA_MATCH', '{"rule":"example"}', now, now, 'CLEAN', 'YARA_MATCH'))
        changed = self.cfg['mount'] + '/media/changed.mkv'
        self.db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?)', (changed, 'PENDING', '{}', now-20, now-5, None, None))
        self.db.execute('INSERT INTO events VALUES(1,?,?,?,?,NULL)', (now, changed, 'FILE_CHANGED', 'size changed'))
        self.db.commit()
        snap = self.reports().snapshot()
        self.assertEqual(len(snap['findings']), 126)
        self.assertEqual(snap['findings'][0]['kind'], 'YARA_MATCH')
        self.assertTrue(snap['findings'][0]['share_path'].startswith('//nas/data/media/'))
        self.assertEqual(snap['findings'][-1]['kind'], 'FILE_CHANGED')

    def test_atomic_success_and_replace_failure_preserves_previous_report(self):
        output = self.root / 'status.json'
        publisher.atomic_publish(output, {'schema_version': 1, 'path': 'ü <tag>'})
        before = output.read_bytes()
        self.assertIn('ü', output.read_text(encoding='utf-8'))
        with patch.object(publisher.os, 'replace', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                publisher.atomic_publish(output, {'changed': True})
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.four-security-*.tmp')), [])

    def test_in_scan_file_change_is_a_current_warning_without_a_metadata_event(self):
        now = time.time()
        path = self.cfg['mount'] + '/media/changing.mkv'
        reason = json.dumps({'reason': 'file changed during scanning'})
        self.db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?)', (path, 'PENDING', reason, now, now, 'CLEAN', 'CLEAN'))
        self.db.commit()
        findings = self.reports().snapshot()['findings']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['kind'], 'FILE_CHANGED')

    def test_mount_validation_rejects_local_wrong_source_and_readonly(self):
        cfg = {'mount': str(self.root), 'source': '//nas/web/reports'}
        valid = {'source': cfg['source'], 'target': str(self.root), 'fstype': 'cifs', 'options': 'rw,nodev'}
        for changes, allowed in [({}, True), ({'fstype': 'ext4'}, False), ({'source': '//nas/other'}, False),
                                 ({'options': 'ro,nodev'}, False), ({'target': str(self.root.parent)}, False)]:
            row = dict(valid, **changes)
            result = type('Result', (), {'stdout': json.dumps({'filesystems': [row]})})()
            with patch.object(publisher.subprocess, 'run', return_value=result):
                if allowed:
                    self.assertEqual(publisher.verify_destination(cfg), self.root / 'status.json')
                else:
                    with self.assertRaises(RuntimeError):
                        publisher.verify_destination(cfg)
        cfg['output_name'] = '../status.json'
        with self.assertRaises(ValueError):
            publisher.verify_destination(cfg)

    def test_failed_read_never_replaces_or_touches_the_report_mount(self):
        with patch.object(publisher, 'Reports') as reports, patch.object(publisher, 'verify_destination') as destination:
            config = self.root / 'scanner.json'
            config.write_text('{}')
            reports.return_value.snapshot.side_effect = sqlite3.OperationalError('database locked')
            with self.assertRaises(sqlite3.OperationalError):
                publisher.publish({'scanner_config': str(config)})
            destination.assert_not_called()

    def test_cifs_prefixpath_display_is_equivalent(self):
        self.assertEqual(publisher.normalized_source('//nas/web[/four-nas/data/security]'),
                         publisher.normalized_source('//nas/web/four-nas/data/security'))

    def test_generated_snapshot_matches_the_sibling_site_contract(self):
        site = Path(__file__).parents[1] / 'dashboard/site/security.js'
        if not site.exists():
            site = Path(__file__).parents[2] / 'four-media/media-hub/site/security.js'
        node = shutil.which('node')
        if not site.exists() or not node:
            self.skipTest('Sibling site and Node required for cross-project contract check')
        self.add_run()
        payload = self.reports().snapshot()
        script = "require(process.argv[1]).validate(JSON.parse(require('fs').readFileSync(0,'utf8')));"
        subprocess.run([node, '-e', script, str(site)], input=json.dumps(payload),
                       text=True, capture_output=True, check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
