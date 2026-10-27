#!/usr/bin/env python3
"""Stopped, journaled migration of the legacy Pi Docker installation. No NAS writes."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import shlex

OLD = 'four-securitycenter'  # Legacy identifiers are intentional in this migrator.
NEW = 'four-security'
OLD_MOUNT = f'/mnt/{OLD}/downloads'
NEW_MOUNT = f'/mnt/{NEW}/downloads'
BACKUPS = Path('/var/backups/four-security-migration')
UNITS = [f'{OLD}.service', f'{OLD}-suite.service'] + [
    f'{OLD}-{job}.{kind}' for job in ('scan', 'discover', 'report') for kind in ('timer', 'service')
] + ['clamav-freshclam.service']
NEW_UNITS = [f'{NEW}.service', f'{NEW}-publish.timer', f'{NEW}-publish.service']


def rewrite_path(value):
    if value == OLD_MOUNT or value.startswith(OLD_MOUNT + '/'):
        return NEW_MOUNT + value[len(OLD_MOUNT):]
    return value


def migrate_database(filename):
    """Only structured path fields change; cached fingerprints/evidence stay intact."""
    db = sqlite3.connect(filename, timeout=5)
    try:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Source database failed integrity_check')
        db.execute('BEGIN IMMEDIATE')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        before = {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                  for table in ('files', 'events', 'runs') if table in tables}
        if 'files' in tables:
            paths = [row[0] for row in db.execute('SELECT path FROM files')]
            rewritten = [rewrite_path(path) for path in paths]
            if len(set(rewritten)) != len(paths):
                raise RuntimeError('Database path collision; nothing was migrated')
            for old, new in zip(paths, rewritten):
                if old != new:
                    db.execute('UPDATE files SET path=? WHERE path=?', (new, old))
        if 'events' in tables:
            for rowid, path in db.execute('SELECT id,path FROM events').fetchall():
                db.execute('UPDATE events SET path=? WHERE id=?', (rewrite_path(path), rowid))
        if 'runs' in tables:
            for rowid, raw in db.execute('SELECT id,scope FROM runs').fetchall():
                scope = json.loads(raw)
                if not isinstance(scope, list) or not all(isinstance(path, str) for path in scope):
                    raise ValueError('Invalid stored run scope')
                db.execute('UPDATE runs SET scope=? WHERE id=?', (json.dumps([rewrite_path(p) for p in scope]), rowid))
            db.execute("""UPDATE runs SET state='interrupted', ended_at=updated_at,
                duration_seconds=MAX(0,updated_at-started_at),
                failure_reason='Stopped for rename; end time is last recorded progress'
                WHERE state='running'""")
        for table, count in before.items():
            if db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] != count:
                raise RuntimeError('Migration changed database row count')
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Migrated database failed integrity_check')
        db.commit()
        return before
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def rewrite_fstab(text):
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if fields and not fields[0].startswith('#') and len(fields) >= 4:
            if fields[1] == NEW_MOUNT:
                raise RuntimeError('Destination mount already appears in fstab')
            if fields[1] == OLD_MOUNT:
                opts = fields[3].split(',')
                if fields[0] != '//192.168.4.46/data' or fields[2] != 'cifs' or 'ro' not in opts or 'rw' in opts:
                    raise RuntimeError('Legacy media entry is not the expected read-only share')
                matches.append(line)
    if len(matches) != 1:
        raise RuntimeError('Expected exactly one legacy media entry in fstab')
    old_line = matches[0]
    return text.replace(old_line, old_line.replace(f'/mnt/{OLD}/', f'/mnt/{NEW}/')
                        .replace(f'/etc/{OLD}/', f'/etc/{NEW}/'), 1)


def restore_fstab(current, original, report_source=None):
    """Undo only suite entries; retain unrelated edits made after deployment."""
    expected = rewrite_fstab(original)
    def mount_line(text, mount):
        rows = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')
                and len(line.split()) >= 4 and line.split()[1] == mount]
        if len(rows) != 1:
            raise RuntimeError('Ambiguous recovery mount entry: ' + mount)
        return rows[0]
    old_line = mount_line(original, OLD_MOUNT)
    new_line = mount_line(expected, NEW_MOUNT)
    current_lines = []
    restored = False
    for line in current.splitlines(keepends=True):
        fields = line.split()
        if fields and not fields[0].startswith('#') and len(fields) >= 4:
            target = fields[1]
            if target in (NEW_MOUNT, OLD_MOUNT):
                if restored or fields != (new_line if target == NEW_MOUNT else old_line).split():
                    raise RuntimeError('Suite media entry changed; reconcile fstab before rollback')
                current_lines.append(old_line + '\n')
                restored = True
                continue
            if target == f'/mnt/{NEW}/reports':
                if fields[0] != report_source or fields[2] != 'cifs' or f'credentials=/etc/{NEW}/report-smb.credentials' not in fields[3].split(','):
                    raise RuntimeError('Report mount differs from publisher config; reconcile fstab before rollback')
                continue
        current_lines.append(line)
    if not restored:
        raise RuntimeError('Suite media mount entry missing during rollback')
    return ''.join(current_lines)


def write_atomic(path, content, mode=None):
    """Preserve existing owner/mode when replacing local configuration."""
    original = path.stat() if path.exists() else None
    fd, temp = tempfile.mkstemp(prefix='.four-security-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode if mode is not None else (original.st_mode & 0o777 if original else 0o600))
        if original and hasattr(os, 'chown'):
            os.chown(temp, original.st_uid, original.st_gid)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def run(args, check=True, timeout=60):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def require_private_root(path):
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise RuntimeError('Recovery directory must be private, root-owned and not a symlink: ' + str(path))


class Migration:
    def __init__(self, root=Path('/'), runner=run):
        self.root = Path(root)
        self.run = runner
        self.snapshot = None
        self.journal = {}

    def path(self, absolute):
        return self.root / Path(absolute).as_posix().lstrip('/')

    def state(self, unit, property_name):
        return self.run(['systemctl', 'show', unit, '--property=' + property_name, '--value'], check=False).stdout.strip()

    def save(self):
        write_atomic(self.snapshot / 'journal.json', json.dumps(self.journal, indent=2) + '\n', 0o600)

    def checkpoint(self, stage):
        self.journal['stage'] = stage
        self.save()

    def inventory(self):
        for name in (f'/etc/{NEW}', f'/var/lib/{NEW}', f'/var/log/{NEW}', f'/mnt/{NEW}'):
            if self.path(name).exists() or self.path(name).is_symlink():
                raise RuntimeError('Destination already exists: ' + name)
        for name in (f'/opt/{OLD}', f'/etc/{OLD}', f'/var/lib/{OLD}', '/var/lib/clamav',
                     '/etc/fstab', '/etc/hostname', '/etc/hosts', f'/opt/{NEW}'):
            p = self.path(name)
            if p.is_symlink() or not p.exists():
                raise RuntimeError('Missing or symlink source: ' + name)
        for filename in (f'/opt/{OLD}/compose.yaml', f'/opt/{OLD}/.env'):
            if not self.path(filename).is_file() or self.path(filename).is_symlink():
                raise RuntimeError('This migrator requires the existing Docker deployment: ' + filename)
        if self.path(f'/etc/logrotate.d/{NEW}').exists():
            raise RuntimeError('Destination logrotate config already exists')
        old_rotation = self.path(f'/etc/logrotate.d/{OLD}')
        if old_rotation.is_symlink():
            raise RuntimeError('Legacy logrotate config is a symlink; review it first')
        if self.path(f'/opt/{NEW}/.env').exists():
            raise RuntimeError('New checkout already has .env; stage a source-only release')
        for name in (f'/etc/{OLD}', f'/var/lib/{OLD}', f'/opt/{OLD}/rules'):
            directory = self.path(name)
            if not directory.is_dir() or directory.is_symlink() or any(p.is_symlink() for p in directory.rglob('*')):
                raise RuntimeError('Symlinks in migration config/state/rules require manual review: ' + name)
        for name in (f'/opt/{NEW}', f'/etc/{OLD}', f'/var/lib/{OLD}', '/var/lib/clamav'):
            p = self.path(name)
            if any(parent.is_symlink() for parent in [p, *p.parents]):
                raise RuntimeError('Symlink in migration path: ' + name)
        cfg = json.loads(self.path(f'/etc/{OLD}/scanner.json').read_text())
        expected = {'mount': OLD_MOUNT, 'state_db': f'/var/lib/{OLD}/scans.sqlite3',
                    'lock_file': f'/var/lib/{OLD}/scan.lock',
                    'rules': f'/opt/{OLD}/rules/media-payload-indicators.yar',
                    'source': '//192.168.4.46/data', 'clam_database': '/var/lib/clamav'}
        if any(cfg.get(k) != v for k, v in expected.items()):
            raise RuntimeError('Unexpected legacy config layout; review before migration')
        rewrite_fstab(self.path('/etc/fstab').read_text())
        identities = {}
        for kind, number in (('passwd', '997'), ('group', '983')):
            entry = self.run(['getent', kind, number]).stdout.strip().split(':')
            if entry[0] not in ('scanner', OLD, NEW) or (kind == 'passwd' and entry[3] != '983'):
                raise RuntimeError('Incompatible scanner identity')
            if entry[0] == OLD and self.run(['getent', kind, NEW], check=False).returncode == 0:
                raise RuntimeError('Destination identity already exists')
            identities[kind] = entry[0]
        units = {}
        for unit in UNITS:
            units[unit] = {name: self.state(unit, name) for name in ('LoadState', 'ActiveState', 'UnitFileState')}
            if units[unit]['LoadState'] not in ('loaded', 'not-found', 'masked'):
                raise RuntimeError('Unexpected legacy unit load state: ' + unit)
        for unit in NEW_UNITS:
            if self.state(unit, 'LoadState') != 'not-found':
                raise RuntimeError('New unit already installed: ' + unit)
        running = self.run(['docker', 'ps', '--filter', f'label=com.docker.compose.project={OLD}',
                            '--format', '{{.ID}}']).stdout.split()
        services = []
        if running:
            containers = json.loads(self.run(['docker', 'inspect', *running]).stdout)
            services = sorted({c['Config']['Labels']['com.docker.compose.service'] for c in containers})
        hostname = self.run(['hostnamectl', '--static']).stdout.strip()
        if not hostname or any(c.isspace() for c in hostname):
            raise RuntimeError('Could not record hostname')
        mounts = {}
        for suffix in ('automount', 'mount'):
            unit = self.run(['systemd-escape', '--path', '--suffix=' + suffix, OLD_MOUNT]).stdout.strip()
            mounts[unit] = self.state(unit, 'ActiveState')
        return {'version': 1, 'stage': 'inventoried', 'hostname': hostname, 'units': units, 'mount_units': mounts,
                'identities': identities, 'running_services': services, 'created': [], 'changed': []}

    def copy(self, source, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.run(['cp', '-a', '--', str(source), str(destination)], timeout=None)

    def compose(self, old=True, *args):
        name = OLD if old else NEW
        return self.run(['docker', 'compose', '--project-directory', f'/opt/{name}',
                         '-f', f'/opt/{name}/compose.yaml', '--profile', '*', *args], timeout=None)

    def stop_old(self):
        for unit, state in self.journal['units'].items():
            if state['LoadState'] != 'not-found':
                self.run(['systemctl', 'stop', unit])
                if state['UnitFileState'] not in ('masked', 'masked-runtime'):
                    self.run(['systemctl', 'disable', unit])
        self.compose(True, 'down')
        remaining = self.run(['pgrep', '-af', r'(^|/)(freshclam|clamscan|yara)( |$)|[f]our_security(center)?\.py'], check=False)
        if remaining.returncode != 1:
            raise RuntimeError('Engine processes remain or process inventory failed; stop their owning jobs')

    def remember_change(self, filename):
        if filename not in self.journal['changed']:
            self.journal['changed'].append(filename)
            self.save()

    def create_copy(self, source, destination):
        self.journal['created'].append('/' + destination.relative_to(self.root).as_posix())
        self.save()  # Recovery knows about the target even if cp fails halfway.
        self.copy(source, destination)

    def apply(self):
        marker = self.path(f'/opt/{NEW}/.migration-snapshot')
        if marker.exists():
            saved = Path(marker.read_text().strip())
            journal = json.loads((saved / 'journal.json').read_text())
            if journal['stage'] != 'complete':
                raise RuntimeError('Partial migration; inspect journal or roll back: ' + str(saved))
            raise RuntimeError('Migration already applied. Use the saved release and journal: ' + str(saved))
        self.journal = self.inventory()
        # Size calculation touches local sources only; never walk a NAS mount.
        paths = [f'/opt/{OLD}', f'/etc/{OLD}', f'/var/lib/{OLD}', '/var/lib/clamav', f'/var/log/{OLD}']
        size = sum(p.stat().st_size for name in paths for p in self.path(name).rglob('*')
                   if p.is_file() and not p.is_symlink())
        backup_parent = self.path(BACKUPS)
        backup_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require_private_root(backup_parent)
        if shutil.disk_usage(backup_parent).free < size * 2 + 128 * 1024 * 1024:
            raise RuntimeError('Insufficient space for stopped backup and migrated state')
        self.snapshot = backup_parent / (time.strftime('%Y%m%d-%H%M%S') + '-' + str(time.time_ns()))
        self.snapshot.mkdir(mode=0o700)
        self.save()
        write_atomic(marker, str(self.snapshot) + '\n', 0o600)
        print('Snapshot / recovery journal:', self.snapshot, flush=True)
        print(f'Rollback: sudo python3 /opt/{NEW}/scripts/migrate-to-four-security.py --rollback {self.snapshot}', flush=True)
        try:
            for filename in ('/etc/fstab', '/etc/hostname', '/etc/hosts', f'/opt/{OLD}'):
                self.copy(self.path(filename), self.snapshot / filename.lstrip('/'))
            for unit in UNITS:
                for suffix in ('', '.d'):
                    source = self.path('/etc/systemd/system/' + unit + suffix)
                    if source.exists() or source.is_symlink():
                        self.copy(source, self.snapshot / 'units' / (unit + suffix))
            cli = self.path('/usr/local/bin/' + OLD)
            if cli.exists() or cli.is_symlink():
                self.copy(cli, self.snapshot / 'legacy-cli')
            self.checkpoint('stopping')
            self.stop_old()
            self.checkpoint('stopped')
            for filename in (f'/etc/{OLD}', f'/var/lib/{OLD}', '/var/lib/clamav', f'/var/log/{OLD}'):
                source = self.path(filename)
                if source.exists():
                    self.copy(source, self.snapshot / filename.lstrip('/'))
            self.checkpoint('backed-up')
            # Hold the old lock across all path/state changes, preventing manual legacy scans.
            import fcntl
            lock = self.path(f'/var/lib/{OLD}/scan.lock')
            existed = lock.exists()
            with lock.open('a') as stream:
                if not existed:
                    if hasattr(os, 'chown'):
                        os.chown(lock, 997, 983)
                    os.chmod(lock, 0o640)
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.transform()
            self.checkpoint('complete')
            print('Migration complete; all jobs remain stopped. Build/check the release before startup.')
            print('Original unit states, schedules and rollback inputs are in:', self.snapshot)
        except BaseException:
            print('Migration stopped at stage:', self.journal.get('stage'), file=sys.stderr)
            print('Use the printed rollback command; do not start a partial installation.', file=sys.stderr)
            raise

    def transform(self):
        for prefix in ('/etc/', '/var/lib/', '/var/log/'):
            source = self.path(prefix + OLD)
            if source.exists():
                self.create_copy(source, self.path(prefix + NEW))
        cfg_path = self.path(f'/etc/{NEW}/scanner.json')
        cfg = json.loads(cfg_path.read_text())
        for key in ('mount', 'state_db', 'lock_file', 'rules'):
            cfg[key] = cfg[key].replace(OLD, NEW)
        write_atomic(cfg_path, json.dumps(cfg, indent=2) + '\n')
        database = self.path(f'/var/lib/{NEW}/scans.sqlite3')
        self.journal['database_counts'] = migrate_database(database) if database.exists() else {}
        self.save()
        env = self.path(f'/opt/{OLD}/.env').read_text()
        saved_intervals = {}
        lines = []
        for line in env.splitlines():
            key, sep, value = line.partition('=')
            if key in ('SCAN_INTERVAL_SECONDS', 'DISCOVER_INTERVAL_SECONDS') and sep:
                if key in saved_intervals:
                    raise RuntimeError('Duplicate schedule setting')
                saved_intervals[key] = value
            else:
                lines.append(line)
        self.journal['intervals'] = saved_intervals
        self.save()
        lines.extend(['SCAN_INTERVAL_SECONDS=0', 'DISCOVER_INTERVAL_SECONDS=0'])
        self.journal['created'].append(f'/opt/{NEW}/.env')
        self.save()
        write_atomic(self.path(f'/opt/{NEW}/.env'), '\n'.join(lines) + '\n', 0o600)
        # Preserve custom rules, not just the release's default copy.
        old_rules = self.path(f'/opt/{OLD}/rules')
        staged_rules = self.path(f'/opt/{NEW}/rules')
        self.copy(staged_rules, self.snapshot / 'staged-rules')
        self.remember_change('rules')
        staged_rules.rename(self.snapshot / 'staged-rules-original')
        self.copy(old_rules, staged_rules)
        # Acceptance fixtures follow the new release; preserve active production
        # rule bytes separately so renaming alone does not invalidate scan caches.
        validation_rule = self.snapshot / 'staged-rules/test-rule.yar'
        if validation_rule.exists():
            self.copy(validation_rule, staged_rules / 'test-rule.yar')
        old_rotation = self.path(f'/etc/logrotate.d/{OLD}')
        if old_rotation.exists():
            self.copy(old_rotation, self.snapshot / 'legacy-logrotate')
            self.remember_change('logrotate')
            old_rotation.rename(self.snapshot / 'legacy-logrotate-original')
            target = self.path(f'/etc/logrotate.d/{NEW}')
            self.journal['created'].append(f'/etc/logrotate.d/{NEW}')
            self.save()
            text = (self.snapshot / 'legacy-logrotate').read_text().replace(OLD, NEW)
            text = text.replace('create 0640 four-security four-security', 'create 0640 997 983')
            write_atomic(target, text, 0o644)
        self.checkpoint('state-migrated')
        for kind, name in self.journal['identities'].items():
            if name == OLD:
                self.remember_change(kind)
                self.run(['usermod' if kind == 'passwd' else 'groupmod', '--login' if kind == 'passwd' else '--new-name', NEW, OLD])
        units = [self.run(['systemd-escape', '--path', '--suffix=' + suffix, OLD_MOUNT]).stdout.strip()
                 for suffix in ('automount', 'mount')]
        for unit in units:
            if self.state(unit, 'LoadState') != 'not-found':
                self.run(['systemctl', 'stop', unit])
        self.journal['created'].append(f'/mnt/{NEW}')
        self.save()
        self.path(NEW_MOUNT).mkdir(parents=True, mode=0o755)
        fstab = self.path('/etc/fstab')
        self.remember_change('fstab')
        write_atomic(fstab, rewrite_fstab(fstab.read_text()))
        self.journal['applied_fstab'] = fstab.read_text()
        self.save()
        self.run(['systemctl', 'daemon-reload'])
        unit = self.run(['systemd-escape', '--path', '--suffix=mount', NEW_MOUNT]).stdout.strip()
        self.run(['systemctl', 'start', unit], timeout=30)
        self.run(['python3', f'/opt/{NEW}/suite', 'check'], timeout=30)
        self.remember_change('hostname')
        self.run(['hostnamectl', 'set-hostname', NEW])
        hosts = self.path('/etc/hosts')
        old_hostname = self.journal['hostname']
        lines = []
        for line in hosts.read_text().splitlines(keepends=True):
            address_part, marker, comment = line.partition('#')
            tokens = address_part.split()
            if tokens and tokens[0] in ('127.0.1.1', '127.0.0.1', '::1'):
                tokens = [tokens[0]] + [NEW if name == old_hostname else name for name in tokens[1:]]
                line = '\t'.join(tokens) + (' #' + comment.rstrip('\n') if marker else '') + '\n'
            lines.append(line)
        self.journal['applied_hosts'] = ''.join(lines)
        self.remember_change('hosts')
        write_atomic(hosts, self.journal['applied_hosts'])

    def rollback(self, snapshot):
        snapshot = Path(snapshot).resolve()
        parent = self.path(BACKUPS).resolve()
        if snapshot.parent != parent or not snapshot.is_dir():
            raise RuntimeError('Snapshot must be a private root-owned direct child of ' + str(parent))
        require_private_root(parent)
        require_private_root(snapshot)
        self.snapshot = snapshot
        self.journal = json.loads((snapshot / 'journal.json').read_text())
        if self.journal['stage'] == 'rolled-back':
            print('Already rolled back:', snapshot)
            return
        if 'hostname' in self.journal['changed']:
            hostname = self.run(['hostnamectl', '--static']).stdout.strip()
            if hostname not in (NEW, self.journal['hostname']):
                raise RuntimeError('Hostname changed after migration; reconcile it before rollback')
        restored_fstab = None
        if 'fstab' in self.journal['changed']:
            publisher_config = self.path(f'/etc/{NEW}/publisher.json')
            source = json.loads(publisher_config.read_text())['source'] if publisher_config.exists() else None
            restored_fstab = restore_fstab(self.path('/etc/fstab').read_text(), (snapshot / 'etc/fstab').read_text(), source)
        for key in ('hosts',):
            current = self.path('/etc/' + key).read_text()
            original = snapshot / 'etc' / key
            applied = self.journal.get('applied_' + key)
            expected = applied
            if expected is None and key == 'fstab':
                expected = rewrite_fstab(original.read_text())
            if key in self.journal['changed'] and current not in (expected, original.read_text()):
                raise RuntimeError(key + ' changed after migration; reconcile it before rollback')
        for unit in NEW_UNITS:
            if self.state(unit, 'LoadState') != 'not-found':
                self.run(['systemctl', 'stop', unit])
                self.run(['systemctl', 'disable', unit], check=False)
        if self.path(f'/opt/{NEW}/.env').exists():
            self.compose(False, 'down')
        # Archive new state before restoring the untouched, stopped legacy paths.
        post = snapshot / ('post-migration-' + str(time.time_ns()))
        post.mkdir(mode=0o700)
        for mount in (f'/mnt/{NEW}/reports', NEW_MOUNT):
            for suffix in ('automount', 'mount'):
                unit = self.run(['systemd-escape', '--path', '--suffix=' + suffix, mount]).stdout.strip()
                self.run(['systemctl', 'stop', unit], check=False)
            mounted = self.run(['findmnt', '-rn', '-M', mount], check=False)
            if mounted.returncode == 0:
                raise RuntimeError('New mount is still present; stop/unmount it before rollback: ' + mount)
        # Fixed allowlist: journal text never selects arbitrary move/remove targets.
        allowed = {f'/etc/{NEW}', f'/var/lib/{NEW}', f'/var/log/{NEW}', f'/opt/{NEW}/.env', f'/mnt/{NEW}', f'/etc/logrotate.d/{NEW}'}
        for name in self.journal['created']:
            if name not in allowed:
                raise RuntimeError('Unexpected recovery target')
            source = self.path(name)
            if source.exists():
                target = post / name.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                source.rename(target)
        for key in ('fstab', 'hosts', 'hostname'):
            if key in self.journal['changed']:
                if key == 'fstab':
                    write_atomic(self.path('/etc/fstab'), restored_fstab)
                else:
                    self.copy(snapshot / 'etc' / key, self.path('/etc/' + key))
        if 'hostname' in self.journal['changed']:
            self.run(['hostnamectl', 'set-hostname', self.journal['hostname']])
        for kind in ('passwd', 'group'):
            if kind in self.journal['changed']:
                current = self.run(['getent', kind, '997' if kind == 'passwd' else '983']).stdout.split(':')[0]
                if current == NEW:
                    self.run(['usermod' if kind == 'passwd' else 'groupmod', '--login' if kind == 'passwd' else '--new-name', OLD, NEW])
                elif current != OLD:
                    raise RuntimeError('Identity changed after migration; reconcile before recovery')
        if 'rules' in self.journal['changed']:
            rules = self.path(f'/opt/{NEW}/rules')
            if rules.exists():
                rules.rename(post / 'new-rules')
            self.copy(snapshot / 'staged-rules', rules)
        if 'logrotate' in self.journal['changed']:
            self.copy(snapshot / 'legacy-logrotate', self.path(f'/etc/logrotate.d/{OLD}'))
        # Cleanup only archives inventoried unit definitions. Restore them if
        # rollback follows cleanup; do not overwrite later edited definitions.
        for unit in UNITS:
            for suffix in ('', '.d'):
                saved = snapshot / 'units' / (unit + suffix)
                target = self.path('/etc/systemd/system/' + unit + suffix)
                if (saved.exists() or saved.is_symlink()) and not (target.exists() or target.is_symlink()):
                    self.copy(saved, target)
        cli = self.path('/usr/local/bin/' + OLD)
        if (snapshot / 'legacy-cli').exists() or (snapshot / 'legacy-cli').is_symlink():
            if not cli.exists() and not cli.is_symlink():
                self.copy(snapshot / 'legacy-cli', cli)
        self.run(['systemctl', 'daemon-reload'])
        # Legacy directories were deliberately not edited; verify DB before restarting.
        old_db = self.path(f'/var/lib/{OLD}/scans.sqlite3')
        if old_db.exists():
            with contextlib.closing(sqlite3.connect(old_db.as_uri() + '?mode=ro', uri=True)) as db:
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise RuntimeError('Legacy DB failed integrity check; use the stopped snapshot for manual recovery')
        for unit, state in self.journal.get('mount_units', {}).items():
            if state == 'active':
                self.run(['systemctl', 'start', unit], timeout=30)
        for name, state in self.journal['units'].items():
            if state['UnitFileState'] in ('enabled', 'enabled-runtime'):
                args = ['systemctl', 'enable'] + (['--runtime'] if state['UnitFileState'] == 'enabled-runtime' else []) + [name]
                self.run(args)
            native_job = name.startswith(OLD + '-') and name.endswith('.service') and name != OLD + '-suite.service'
            if state['ActiveState'] == 'active' and not native_job:
                self.run(['systemctl', 'start', name])
        if self.journal['running_services']:
            # Restart only the previously running services, not every optional profile.
            self.compose(True, 'up', '-d', *self.journal['running_services'])
        self.checkpoint('rolled-back')
        self.path(f'/opt/{NEW}/.migration-snapshot').unlink(missing_ok=True)
        print('Legacy installation restored; new state retained at:', post)

    def cleanup_preview(self, snapshot):
        """Print explicit archive commands; never delete data or execute cleanup."""
        snapshot = Path(snapshot).resolve()
        if snapshot.parent != self.path(BACKUPS).resolve():
            raise RuntimeError('Unexpected migration snapshot location')
        require_private_root(snapshot)
        journal = json.loads((snapshot / 'journal.json').read_text())
        if journal['stage'] != 'complete':
            raise RuntimeError('Only a completed migration can be retired')
        for unit in UNITS:
            if unit == 'clamav-freshclam.service':
                continue
            if self.state(unit, 'ActiveState') not in ('inactive', 'failed', ''):
                raise RuntimeError('Legacy unit is still active: ' + unit)
            if self.state(unit, 'UnitFileState') in ('enabled', 'enabled-runtime'):
                raise RuntimeError('Legacy unit is still enabled: ' + unit)
        archive = snapshot / 'retired-units'
        commands = ['sudo install -d -m 0700 ' + shlex.quote(str(archive))]
        for unit in UNITS:
            if unit == 'clamav-freshclam.service':
                continue
            for suffix in ('', '.d'):
                name = unit + suffix
                source = self.path('/etc/systemd/system/' + name)
                saved = snapshot / 'units' / name
                if not (source.exists() or source.is_symlink()):
                    continue
                if not (saved.exists() or saved.is_symlink()):
                    raise RuntimeError('Unit was not inventoried: ' + name)
                if source.is_symlink() or saved.is_symlink():
                    same = source.is_symlink() and saved.is_symlink() and os.readlink(source) == os.readlink(saved)
                elif source.is_dir():
                    actual = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file() and not p.is_symlink()}
                    prior = {p.relative_to(saved): p.read_bytes() for p in saved.rglob('*') if p.is_file() and not p.is_symlink()}
                    same = actual == prior and not any(p.is_symlink() for p in source.rglob('*'))
                else:
                    same = source.read_bytes() == saved.read_bytes()
                if not same or (archive / name).exists():
                    raise RuntimeError('Unit changed or archive target exists: ' + name)
                commands.append('sudo mv -- ' + shlex.quote(str(source)) + ' ' + shlex.quote(str(archive / name)))
        cli = self.path('/usr/local/bin/' + OLD)
        if cli.is_symlink() and str(cli.resolve()).startswith(str(self.path(f'/opt/{OLD}')) + os.sep):
            commands.append('sudo mv -- ' + shlex.quote(str(cli)) + ' ' + shlex.quote(str(snapshot / 'retired-cli')))
        commands.append('sudo systemctl daemon-reload')
        print('# After live acceptance only; review and run these exact commands manually.')
        print('\n'.join(commands))
        print('# Original data, source, snapshots and images are deliberately retained for rollback.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dry-run', action='store_true')
    group.add_argument('--apply', action='store_true')
    group.add_argument('--rollback', type=Path)
    group.add_argument('--cleanup-preview', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run with sudo on the Linux Pi')
    checkout = Path(__file__).resolve().parents[1]
    if checkout != Path('/opt/four-security') or checkout.stat().st_uid != 0 or checkout.stat().st_mode & 0o022:
        parser.error('Stage a root-owned, non-group-writable release at /opt/four-security')
    migration = Migration()
    try:
        if args.dry_run:
            print(json.dumps(migration.inventory(), indent=2))
            print('Dry-run only; no changes made. Original intervals will be saved and paused during acceptance.')
        elif args.cleanup_preview:
            migration.cleanup_preview(args.cleanup_preview)
        else:
            import fcntl
            with open('/run/lock/four-security-migration.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.rollback:
                    migration.rollback(args.rollback)
                else:
                    migration.apply()
        return 0
    except Exception as exc:
        print('BLOCKED:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
