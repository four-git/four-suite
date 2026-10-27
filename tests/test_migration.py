import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
import sys
import types
from contextlib import closing

spec = importlib.util.spec_from_file_location('migration', Path(__file__).parents[1] / 'scripts/migrate-to-four-security.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MigrationDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dbpath = self.root / 'scan.sqlite3'
        self.db = sqlite3.connect(self.dbpath)
        self.addCleanup(self.db.close)
        self.db.executescript('''CREATE TABLE files(path TEXT PRIMARY KEY,versions TEXT,size INTEGER,mtime INTEGER);
            CREATE TABLE events(id INTEGER PRIMARY KEY,path TEXT,detail TEXT);''')

    def test_legacy_schema_cache_and_evidence_preserved(self):
        old = m.OLD_MOUNT + '/media/file.mkv'
        unrelated = m.OLD_MOUNT + '-other/file.mkv'
        self.db.executemany('INSERT INTO files VALUES(?,?,?,?)', [(old, 'fingerprint', 42, 123), (unrelated, 'other', 5, 10)])
        self.db.execute('INSERT INTO events VALUES(1,?,?)', (old, old + ' engine evidence'))
        self.db.commit()
        counts = m.migrate_database(self.dbpath)
        self.assertEqual(counts, {'files': 2, 'events': 1})
        self.assertEqual(self.db.execute('SELECT versions,size,mtime FROM files WHERE path=?', (m.NEW_MOUNT + '/media/file.mkv',)).fetchone(), ('fingerprint', 42, 123))
        self.assertEqual(self.db.execute('SELECT detail FROM events').fetchone()[0], old + ' engine evidence')
        self.assertTrue(self.db.execute('SELECT 1 FROM files WHERE path=?', (unrelated,)).fetchone())
        self.assertEqual(m.migrate_database(self.dbpath), counts)

    def test_collisions_roll_back_entire_transaction(self):
        self.db.executemany('INSERT INTO files VALUES(?,?,?,?)', [(m.OLD_MOUNT+'/x', 'a', 1, 2), (m.NEW_MOUNT+'/x', 'b', 1, 2)])
        self.db.commit()
        before = self.db.execute('SELECT * FROM files ORDER BY path').fetchall()
        with self.assertRaisesRegex(RuntimeError, 'collision'):
            m.migrate_database(self.dbpath)
        self.assertEqual(self.db.execute('SELECT * FROM files ORDER BY path').fetchall(), before)

    def test_run_scopes_and_interrupted_state(self):
        self.db.execute('''CREATE TABLE runs(id INTEGER PRIMARY KEY,scope TEXT,state TEXT,started_at REAL,
            updated_at REAL,ended_at REAL,duration_seconds REAL,failure_reason TEXT)''')
        self.db.execute('INSERT INTO runs VALUES(1,?,?,10,15,NULL,NULL,NULL)', (json.dumps([m.OLD_MOUNT+'/media', '/other']), 'running'))
        self.db.commit()
        m.migrate_database(self.dbpath)
        row = self.db.execute('SELECT scope,state,ended_at,duration_seconds FROM runs').fetchone()
        self.assertEqual(json.loads(row[0]), [m.NEW_MOUNT+'/media', '/other'])
        self.assertEqual(row[1:], ('interrupted', 15, 5))

    def test_fstab_preserves_unrelated_entries_and_rejects_ambiguity(self):
        entry = f'//192.168.4.46/data {m.OLD_MOUNT} cifs credentials=/etc/{m.OLD}/smb.credentials,ro 0 0\n'
        prefix = '# Other services\nUUID=example / ext4 defaults 0 1\n'
        converted = m.rewrite_fstab(prefix + entry)
        self.assertTrue(converted.startswith(prefix))
        self.assertIn(m.NEW_MOUNT, converted)
        self.assertIn('/etc/four-security/smb.credentials', converted)
        for text in ('', entry + entry, entry.replace(',ro', ',rw'), entry + converted):
            with self.assertRaises(RuntimeError):
                m.rewrite_fstab(text)

    def test_rollback_preserves_other_mounts_and_removes_only_matching_report_mount(self):
        original = f'//192.168.4.46/data {m.OLD_MOUNT} cifs credentials=/etc/{m.OLD}/smb.credentials,ro 0 0\n'
        report = f'//nas/web/reports /mnt/{m.NEW}/reports cifs credentials=/etc/{m.NEW}/report-smb.credentials,rw 0 0\n'
        other = 'UUID=another /archive ext4 defaults 0 1\n'
        current = m.rewrite_fstab(original) + report + other
        self.assertEqual(m.restore_fstab(current, original, '//nas/web/reports'), original + other)
        with self.assertRaises(RuntimeError):
            m.restore_fstab(current, original, '//nas/wrong')

    def test_private_recovery_paths_reject_public_nonroot_and_symlink(self):
        path = Mock()
        path.is_symlink.return_value = False
        path.stat.return_value = types.SimpleNamespace(st_uid=0, st_mode=0o700)
        m.require_private_root(path)
        for uid, mode, symlink in [(1, 0o700, False), (0, 0o755, False), (0, 0o700, True)]:
            path.is_symlink.return_value = symlink
            path.stat.return_value = types.SimpleNamespace(st_uid=uid, st_mode=mode)
            with self.assertRaises(RuntimeError): m.require_private_root(path)


class HostMigrationTests(unittest.TestCase):
    def setUp(self):
        # Exercise the file/state machine on every host. Actual systemd, UID
        # enforcement, CIFS and Linux locks still require Pi acceptance.
        private = patch.object(m, 'require_private_root')
        private.start()
        self.addCleanup(private.stop)
        if hasattr(os, 'chown'):
            ownership = patch.object(m.os, 'chown')
            ownership.start()
            self.addCleanup(ownership.stop)
        if os.name != 'posix':
            lock = patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None)})
            lock.start()
            self.addCleanup(lock.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.host = m.Migration(self.root, self.command)
        self.calls = []
        self.hostname = m.OLD
        self.identities = {'passwd': 'scanner', 'group': 'scanner'}
        self.units = {name: {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'} for name in m.UNITS}
        self.units[m.OLD+'.service'].update(ActiveState='active', UnitFileState='enabled')
        for directory in (f'/opt/{m.OLD}/rules', f'/opt/{m.NEW}/rules', f'/etc/{m.OLD}', f'/var/lib/{m.OLD}', '/var/lib/clamav', '/etc/systemd/system'):
            self.host.path(directory).mkdir(parents=True, exist_ok=True)
        self.host.path('/etc/hostname').write_text(m.OLD+'\n')
        self.host.path('/etc/hosts').write_text('127.0.0.1 localhost\n127.0.1.1 '+m.OLD+'\n')
        self.host.path('/etc/fstab').write_text(f'//192.168.4.46/data {m.OLD_MOUNT} cifs credentials=/etc/{m.OLD}/smb.credentials,ro 0 0\n')
        config = {'mount': m.OLD_MOUNT, 'state_db': f'/var/lib/{m.OLD}/scans.sqlite3', 'lock_file': f'/var/lib/{m.OLD}/scan.lock',
                  'rules': f'/opt/{m.OLD}/rules/media-payload-indicators.yar', 'source': '//192.168.4.46/data', 'clam_database': '/var/lib/clamav'}
        self.host.path(f'/etc/{m.OLD}/scanner.json').write_text(json.dumps(config))
        self.host.path(f'/opt/{m.OLD}/.env').write_text('SUITE_IMAGE=sha256:old\nSCAN_INTERVAL_SECONDS=21600\nDISCOVER_INTERVAL_SECONDS=3600\n')
        self.host.path(f'/opt/{m.OLD}/compose.yaml').write_text('name: four-securitycenter\nservices: {}\n')
        self.host.path(f'/opt/{m.OLD}/rules/custom.yar').write_text('old custom rules')
        self.host.path(f'/opt/{m.NEW}/rules/release.yar').write_text('new release rules')
        with closing(sqlite3.connect(self.host.path(config['state_db']))) as db:
            db.execute('CREATE TABLE files(path TEXT PRIMARY KEY)')
            db.execute('INSERT INTO files VALUES(?)', (m.OLD_MOUNT+'/media/x',))
            db.commit()

    def command(self, args, check=True, timeout=60):
        self.calls.append(args)
        code, output = 0, ''
        if args[0] == 'getent':
            kind, key = args[1:]
            name = self.identities[kind]
            if key not in ('997', '983', name): code = 2
            else: output = f'{name}:x:997:983::/nonexistent:/usr/sbin/nologin\n' if kind == 'passwd' else f'{name}:x:983:\n'
        elif args[:2] == ['systemctl', 'show']:
            state = self.units.get(args[2], {'LoadState': 'not-found'})
            output = state.get(args[3].split('=')[1], '')
        elif args[0] == 'hostnamectl':
            if args[1] == '--static': output = self.hostname
            else:
                self.hostname = args[2]
                self.host.path('/etc/hostname').write_text(self.hostname+'\n')
        elif args[0] == 'cp':
            source, target = map(Path, args[-2:])
            if source.is_dir(): shutil.copytree(source, target, symlinks=True)
            else: shutil.copy2(source, target)
        elif args[0] == 'pgrep': code = 1
        elif args[0] == 'findmnt': code = 1
        elif args[0] == 'systemd-escape': output = 'stub-'+args[2].split('=')[1]
        elif args[0] in ('usermod', 'groupmod'):
            self.identities['passwd' if args[0] == 'usermod' else 'group'] = args[2]
        result = subprocess.CompletedProcess(args, code, output, '')
        if check and code: raise subprocess.CalledProcessError(code, args)
        return result

    def test_dry_inventory_writes_nothing(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        self.host.inventory()
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))
        self.assertFalse(any(c[0] == 'cp' or c[:2] == ['systemctl', 'stop'] for c in self.calls))

    def test_apply_and_rollback_preserve_old_data_and_pause_schedules(self):
        self.host.apply()
        self.assertEqual(self.hostname, m.NEW)
        env = self.host.path(f'/opt/{m.NEW}/.env').read_text()
        self.assertIn('SCAN_INTERVAL_SECONDS=0', env)
        self.assertEqual(self.host.journal['intervals']['SCAN_INTERVAL_SECONDS'], '21600')
        with closing(sqlite3.connect(self.host.path(f'/var/lib/{m.NEW}/scans.sqlite3'))) as db:
            self.assertEqual(db.execute('SELECT path FROM files').fetchone()[0], m.NEW_MOUNT+'/media/x')
        snapshot = self.host.snapshot
        self.host.rollback(snapshot)
        self.assertEqual(self.hostname, m.OLD)
        self.assertFalse(self.host.path(f'/var/lib/{m.NEW}').exists())
        self.assertIn(m.OLD_MOUNT, self.host.path('/etc/fstab').read_text())
        self.assertTrue(self.host.path(f'/opt/{m.NEW}/rules/release.yar').exists())
        self.host.rollback(snapshot)

    def test_destination_conflict_does_not_stop_services(self):
        self.host.path(f'/var/lib/{m.NEW}').mkdir()
        with self.assertRaises(RuntimeError): self.host.apply()
        self.assertFalse(any(c[:2] == ['systemctl', 'stop'] for c in self.calls))

    def test_failure_during_mount_activation_can_roll_back(self):
        original = self.host.run
        def failing(args, **kwargs):
            if args[:3] == ['systemctl', 'start', 'stub-mount']:
                raise subprocess.CalledProcessError(1, args)
            return original(args, **kwargs)
        self.host.run = failing
        with self.assertRaises(subprocess.CalledProcessError): self.host.apply()
        self.host.run = original
        self.host.rollback(self.host.snapshot)
        self.assertEqual(self.hostname, m.OLD)
        self.assertFalse(self.host.path(f'/etc/{m.NEW}').exists())

    def test_installed_logrotate_is_migrated_and_restored(self):
        legacy = self.host.path('/etc/logrotate.d/' + m.OLD)
        legacy.parent.mkdir()
        text = f'/var/log/{m.OLD}/*.log {{\n create 0640 {m.OLD} {m.OLD}\n}}\n'
        legacy.write_text(text)
        self.host.apply()
        self.assertFalse(legacy.exists())
        converted = self.host.path('/etc/logrotate.d/' + m.NEW).read_text()
        self.assertIn('create 0640 997 983', converted)
        self.host.rollback(self.host.snapshot)
        self.assertEqual(legacy.read_text(), text)

    def test_cleanup_preview_prints_only_and_rollback_restores_retired_units(self):
        unit = self.host.path('/etc/systemd/system/' + m.OLD + '.service')
        unit.write_text('[Service]\nType=oneshot\n')
        self.host.apply()
        self.units[m.OLD+'.service'].update(ActiveState='inactive', UnitFileState='disabled')
        with patch('builtins.print') as output:
            self.host.cleanup_preview(self.host.snapshot)
        self.assertTrue(unit.exists())
        text = '\n'.join(str(call.args[0]) for call in output.call_args_list)
        self.assertIn('sudo mv --', text)
        self.assertNotIn(' rm ', text)
        archive = self.host.snapshot / 'retired-units'
        archive.mkdir()
        unit.rename(archive / unit.name)
        self.host.rollback(self.host.snapshot)
        self.assertTrue(unit.exists())


if __name__ == '__main__':
    unittest.main()
