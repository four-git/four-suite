#!/usr/bin/env python3
"""Read-only, bounded NAS scanner. State and reports stay on the Pi."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time
import signal
import socket

STATUSES = ('CLEAN', 'MALWARE_DETECTED', 'YARA_MATCH', 'SKIPPED_SIZE_LIMIT',
            'SKIPPED_POLICY', 'PARTIALLY_SCANNED', 'SCAN_ERROR', 'PENDING', 'POLICY_VIOLATION')


def clam_daemon(cfg, request='VERSION'):
    """Local-only daemon control; no TCP port or network access is needed."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(cfg.get('clam_socket', '/tmp/four-security-clamd.sock'))
        sock.sendall(('z' + request + '\0').encode())
        reply = b''
        while b'\0' not in reply:
            part = sock.recv(4096)
            if not part:
                raise RuntimeError('ClamAV daemon closed its socket')
            reply += part
            if len(reply) > 8192:
                raise RuntimeError('Oversized ClamAV daemon reply')
        return reply.rstrip(b'\0').decode()


def file_policy(fd, path):
    """Identify active content without executing it or trusting its filename."""
    head = os.pread(fd, 4096, 0)
    kind = None
    if head.startswith(b'MZ') and len(head) >= 64:
        offset = int.from_bytes(head[60:64], 'little')
        if 64 <= offset <= os.fstat(fd).st_size - 4 and os.pread(fd, 4, offset) == b'PE\0\0':
            kind = 'Windows executable (PE)'
    elif head.startswith(b'\x7fELF'):
        kind = 'Linux executable (ELF)'
    elif head[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        kind = 'Mach-O executable'
    elif head.startswith(b'#!'):
        kind = 'Executable script'
    suffix = Path(path).suffix.lower()
    if kind or suffix in {'.exe', '.dll', '.scr', '.com', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.lnk', '.hta', '.sh', '.jar'}:
        return {'reason': 'Active content is not allowed in media download roots',
                'detected_type': kind or 'Executable/script filename', 'extension': suffix,
                'action': 'Flagged for review; source file was not executed, moved or deleted'}
    return None


def command(args, timeout=20, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)


def verify_mount(cfg):
    mount = Path(cfg['mount'])
    if not mount.is_dir():
        raise RuntimeError('SCAN_ERROR: mount directory unavailable')
    # stat/is_dir on the automount point itself need not activate autofs. Opening
    # the directory triggers it before findmnt inspects the covering filesystem.
    # Callers bound health/preflight with a timeout; this never writes to the NAS.
    with os.scandir(mount):
        pass
    r = command(['findmnt', '-J', '-T', str(mount), '-o', 'SOURCE,TARGET,FSTYPE,OPTIONS'])
    rows = json.loads(r.stdout).get('filesystems', []) if r.returncode == 0 else []
    # Some util-linux versions report the systemd autofs entry alongside the
    # filesystem mounted over it. Permit that wrapper at this exact target;
    # still require one unambiguous backing filesystem and validate it below.
    automounts = [row for row in rows if row.get('fstype') == 'autofs']
    rows = [row for row in rows if row.get('fstype') != 'autofs']
    if (len(rows) != 1 or len(automounts) > 1 or
            any(Path(row.get('target', '')) != mount for row in automounts)):
        raise RuntimeError('SCAN_ERROR: mount missing or ambiguous')
    m = rows[0]
    if (m['fstype'] != 'cifs' or m['source'] != cfg['source'] or
            Path(m['target']) != mount or 'ro' not in m['options'].split(',') or
            'rw' in m['options'].split(',')):
        raise RuntimeError('SCAN_ERROR: expected read-only CIFS source/target not mounted')
    for relative in cfg['expected_dirs']:
        if not (mount / relative).is_dir():
            raise RuntimeError('SCAN_ERROR: expected NAS directory missing: ' + relative)
    return m


def engine_versions(cfg):
    cv = command(['clamscan', '--version'])
    yv = command([sys.executable, '/opt/four-security/src/yara_x_runner.py', '--version']
                 if cfg.get('yara_mode') == 'yara-x' else ['yara', '--version'])
    if cv.returncode or yv.returncode:
        raise RuntimeError('SCAN_ERROR: scanner version check failed')
    if cfg.get('clam_mode') == 'daemon':
        daemon_version = clam_daemon(cfg)
        if daemon_version.split('/')[:2] != cv.stdout.strip().split('/')[:2]:
            clam_daemon(cfg, 'RELOAD')
            raise RuntimeError('ClamAV daemon is reloading signatures; retry when ready')
    rules = Path(cfg['rules']).read_bytes()
    dbs = [p for p in Path(cfg['clam_database']).iterdir() if p.suffix in ('.cvd', '.cld')]
    if not dbs:
        raise RuntimeError('SCAN_ERROR: no ClamAV databases')
    daily = [p for p in dbs if p.stem == 'daily']
    if not daily:
        raise RuntimeError('SCAN_ERROR: daily signatures missing')
    age = time.time() - max(p.stat().st_mtime for p in daily)
    if age > cfg['signature_max_age_hours'] * 3600:
        raise RuntimeError('SCAN_ERROR: daily signatures stale')
    db_stamp = sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns) for p in dbs)
    details = {'clamav': cv.stdout.strip(), 'yara': yv.stdout.strip(),
               'rules_sha256': hashlib.sha256(rules).hexdigest(), 'databases': db_stamp,
               'yara_coverage': cfg.get('rules_description', 'unspecified rule coverage')}
    if cfg.get('yara_mode') == 'yara-x':
        details['yara_adapter_sha256'] = hashlib.sha256(Path('/opt/four-security/src/yara_x_runner.py').read_bytes()).hexdigest()
    policy = {k: cfg[k] for k in ('clam_max_bytes', 'clam_scan_bytes', 'yara_max_bytes', 'engine_timeout')}
    policy['clam_scan_time_ms'] = cfg.get('clam_scan_time_ms', 120000)
    policy.update(clam_mode=cfg.get('clam_mode', 'standalone'), media_policy=cfg.get('media_policy', False))
    policy['yara_seconds_per_gib'] = cfg.get('yara_seconds_per_gib', 120)
    policy['yara_mode'] = cfg.get('yara_mode', 'classic')
    return details, hashlib.sha256(json.dumps([details, policy], sort_keys=True).encode()).hexdigest()


def combine(clam, yara):
    if clam == 'MALWARE_DETECTED':
        return clam
    if yara == 'YARA_MATCH':
        return yara
    if 'SCAN_ERROR' in (clam, yara):
        return 'SCAN_ERROR'
    if clam == yara == 'CLEAN':
        return 'CLEAN'
    if clam == yara == 'SKIPPED_SIZE_LIMIT':
        return 'SKIPPED_SIZE_LIMIT'
    return 'PARTIALLY_SCANNED'


def interpret(engine, rc, output):
    if engine == 'clam':
        found = [s for s in output.splitlines() if s.endswith(' FOUND')]
        real = [s for s in found if 'Heuristics.Limits.Exceeded' not in s]
        if real:
            return 'MALWARE_DETECTED'
        if 'Heuristics.Limits.Exceeded' in output:
            size_limits = ('Heuristics.Limits.Exceeded.MaxFileSize', 'Heuristics.Limits.Exceeded.MaxScanSize')
            return 'SKIPPED_SIZE_LIMIT' if rc in (0, 1) and any(x in output for x in size_limits) else 'SCAN_ERROR'
        if rc == 0 and not output.strip():
            return 'CLEAN'
        return 'SCAN_ERROR'
    if rc != 0:
        return 'SCAN_ERROR'
    return 'YARA_MATCH' if output.strip() else 'CLEAN'


def engine_budget(engine, size, cfg):
    base = cfg.get('engine_timeout', 360)
    if engine == 'yara':
        gib = (size + 1073741823) // 1073741824
        return max(base, gib * cfg.get('yara_seconds_per_gib', 120))
    return base


def scan_fd(fd, size, cfg, deadline):
    results = {}
    evidence = {}
    for engine in ('clam', 'yara'):
        limit = cfg['clam_max_bytes'] if engine == 'clam' else cfg['yara_max_bytes']
        if (limit and size > limit) or (engine == 'clam' and size >= 2_000_000_000):
            results[engine] = 'SKIPPED_SIZE_LIMIT'
            evidence[engine] = {'attempted': False, 'reason': 'file exceeds configured or engine size limit'}
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results[engine] = 'SCAN_ERROR'
            evidence[engine] = {'attempted': False, 'reason': 'job time budget exhausted'}
            continue
        target = '/proc/self/fd/' + str(fd)
        if engine == 'clam':
            args = ['clamscan', '--infected', '--no-summary', '--alert-exceeds-max',
                    '--max-filesize=' + str(cfg['clam_max_bytes']),
                    '--max-scansize=' + str(cfg['clam_scan_bytes']),
                    '--max-scantime=' + str(cfg.get('clam_scan_time_ms', 120000)), target]
            if cfg.get('clam_mode') == 'daemon':
                args = ['clamdscan', '--fdpass', '--infected', '--no-summary',
                        '--config-file=/tmp/four-security-clamd.conf', target]
        else:
            args = ['yara', '--print-meta', '--timeout=' + str(engine_budget(engine, size, cfg)), cfg['rules'], target]
            if cfg.get('yara_mode') == 'yara-x':
                args = [sys.executable, '/opt/four-security/src/yara_x_runner.py',
                        '--timeout', str(engine_budget(engine, size, cfg)), '--rules', cfg['rules'], target]
        try:
            r = command(args, timeout=min(engine_budget(engine, size, cfg), remaining), pass_fds=(fd,))
            output = r.stdout + r.stderr
            results[engine] = interpret(engine, r.returncode, output)
            evidence[engine] = {'attempted': True, 'exit': r.returncode, 'output': output[-4000:]}
        except (subprocess.TimeoutExpired, OSError) as e:
            results[engine] = 'SCAN_ERROR'
            evidence[engine] = {'attempted': True, 'reason': str(e)}
    return results, evidence


def database(path):
    db = sqlite3.connect(path, timeout=5)
    db.execute('''CREATE TABLE IF NOT EXISTS files (
        path TEXT PRIMARY KEY, share TEXT, size INTEGER, mtime INTEGER,
        stable_since REAL, versions TEXT, status TEXT, clam TEXT, yara TEXT,
        last_attempt REAL, last_success REAL, reason TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY, time REAL, path TEXT, kind TEXT, detail TEXT)''')
    db.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY, action TEXT NOT NULL, scope TEXT NOT NULL,
        dry_run INTEGER NOT NULL, started_at REAL NOT NULL, ended_at REAL,
        updated_at REAL NOT NULL, duration_seconds REAL, state TEXT NOT NULL,
        failure_reason TEXT, summary TEXT NOT NULL)""")
    if 'run_id' not in {r[1] for r in db.execute('PRAGMA table_info(events)')}:
        db.execute('ALTER TABLE events ADD COLUMN run_id INTEGER REFERENCES runs(id)')
    db.execute('CREATE INDEX IF NOT EXISTS events_run ON events(run_id,id)')
    db.commit()
    return db


def within(path, root):
    return path == root or root in path.parents


def _scan(cfg, dry=False, target=None, discover_only=False, run_id=None, progress=None):
    versions, fingerprint = engine_versions(cfg)
    verify_mount(cfg)
    mount = Path(cfg['mount'])
    roots = [mount / p for p in cfg['roots']]
    if any(not within(p.resolve(), mount) for p in roots):
        raise RuntimeError('SCAN_ERROR: root escapes mount')
    if target:
        candidate = Path(target).absolute()
        if not any(within(candidate, root) for root in roots):
            raise RuntimeError('SCAN_ERROR: selected target outside allowed roots')
        roots = [candidate]
    db = database(cfg['state_db'])
    try:
        now = time.time()
        deadline = time.monotonic() + cfg['max_runtime_seconds']
        summary = {'dry_run': dry, 'counts': {}, 'versions': versions, 'visited': 0,
                   'scan_attempts': 0, 'engine_attempts': {'clam': 0, 'yara': 0}, 'cached': 0, 'discovery_truncated': False}

        def count(status):
            summary['counts'][status] = summary['counts'].get(status, 0) + 1
            if progress:
                progress(summary)

        def walk_error(error):
            raise RuntimeError('SCAN_ERROR: cannot enumerate directory: ' + str(error))

        def candidates():
            for root in roots:
                if not root.exists():
                    raise RuntimeError('SCAN_ERROR: selected root missing: ' + str(root))
                if root.is_file() or root.is_symlink():
                    yield root
                else:
                    for base, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                        dirs[:] = sorted(d for d in dirs if not Path(base, d).is_symlink())
                        for name in sorted(names):
                            yield Path(base, name)

        # Prioritize never-scanned and oldest attempts so daily signature updates
        # cannot repeatedly consume the budget on only the first alphabetic files.
        pending_paths = []
        for path in candidates():
            if len(pending_paths) >= cfg.get('max_discovery_files', 100000) or time.monotonic() >= deadline:
                summary['discovery_truncated'] = True
                break
            pending_paths.append(path)
        records = {row[0]: row[1:] for row in db.execute('SELECT path,COALESCE(last_attempt,0),versions,status,size,mtime FROM files')}
        def priority(path):
            root_priority = next((i for i, root in enumerate(roots) if within(path, root)), len(roots))
            old_record = records.get(str(path), (0, '', 'PENDING', None, None))
            st = path.lstat()
            cached = old_record[1] == fingerprint and old_record[2] not in ('SCAN_ERROR', 'PENDING') and old_record[3:] == (st.st_size, st.st_mtime_ns)
            retry_wait = old_record[2] == 'SCAN_ERROR' and old_record[1] == fingerprint and now - old_record[0] < cfg.get('retry_seconds', 21600)
            return (int(cached or retry_wait), old_record[0], root_priority, str(path))
        pending_paths.sort(key=priority)
        for path in pending_paths:
            if time.monotonic() >= deadline or summary['visited'] >= cfg['max_files_per_run']:
                summary['discovery_truncated'] = True
                break
            summary['visited'] += 1
            if path.is_symlink():
                count('SKIPPED_POLICY')
                continue
            # Revalidate before every file: a lost mount must not look like an empty clean folder.
            verify_mount(cfg)
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode):
                count('SKIPPED_POLICY')
                continue
            key = str(path)
            old = db.execute('SELECT size,mtime,stable_since,versions,status,last_success,last_attempt,clam,yara,reason FROM files WHERE path=?', (key,)).fetchone()
            changed = old is None or old[:2] != (st.st_size, st.st_mtime_ns)
            since = now if changed else old[2]
            if changed and old:
                db.execute('INSERT INTO events(time,path,kind,detail,run_id) VALUES(?,?,?,?,?)',
                           (time.time(), key, 'FILE_CHANGED', 'size or modification time changed', run_id))
            stable = now - since >= cfg['stable_seconds'] and now - st.st_mtime >= cfg['stable_seconds']
            if old and not changed and (discover_only or (old[4] == 'SCAN_ERROR' and old[3] == fingerprint and now - (old[6] or 0) < cfg.get('retry_seconds', 21600))):
                # Discovery is inventory, never a replacement scan verdict. Preserve
                # attempts/evidence even when signatures changed since that verdict.
                count(old[4])
                continue
            result, engines, evidence = 'PENDING', {}, {}
            attempted, success = old[6] if old else None, old[5] if old else None
            if not changed and stable and old[3] == fingerprint and old[4] not in ('SCAN_ERROR', 'PENDING'):
                result = old[4]
                summary['cached'] += 1
                db.commit()
                count(result)
                continue
            if stable and not dry and not discover_only:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    before = os.fstat(fd)
                    if (before.st_size, before.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                        since = now
                    else:
                        attempted = time.time()
                        policy_finding = file_policy(fd, path) if cfg.get('media_policy') else None
                        if policy_finding:
                            engines, evidence = {'clam': 'SKIPPED_POLICY', 'yara': 'SKIPPED_POLICY'}, policy_finding
                        else:
                            # The batch budget controls admission of the next file;
                            # it must not interrupt a file already being inspected.
                            file_deadline = time.monotonic() + sum(engine_budget(name, st.st_size, cfg) for name in ('clam', 'yara')) + 5
                            engines, evidence = scan_fd(fd, st.st_size, cfg, file_deadline)
                        after = os.fstat(fd)
                        current = path.lstat()
                        _, after_fingerprint = engine_versions(cfg)
                        if after_fingerprint != fingerprint:
                            result, since = 'PENDING', now
                            evidence['reason'] = 'engine/rules/signatures changed during scanning'
                        elif ((after.st_size, after.st_mtime_ns, after.st_ino) !=
                                (before.st_size, before.st_mtime_ns, before.st_ino) or
                                (current.st_size, current.st_mtime_ns, current.st_ino) !=
                                (before.st_size, before.st_mtime_ns, before.st_ino)):
                            result, since = 'PENDING', now
                            evidence['reason'] = 'file changed during scanning'
                        else:
                            result = 'POLICY_VIOLATION' if policy_finding else combine(engines['clam'], engines['yara'])
                            if result == 'CLEAN':
                                success = attempted
                        attempted_engines = [] if policy_finding else [name for name in engines if evidence.get(name, {}).get('attempted', engines[name] != 'SKIPPED_SIZE_LIMIT')]
                        summary['scan_attempts'] += int(bool(attempted_engines))
                        for name in attempted_engines:
                            summary['engine_attempts'][name] += 1
                finally:
                    os.close(fd)
            elif stable and dry:
                evidence['reason'] = 'eligible; dry-run does not execute engines'
            if not dry:
                db.execute('''INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (key, cfg['source'], st.st_size, st.st_mtime_ns, since,
                            fingerprint if attempted else '', result, engines.get('clam'),
                            engines.get('yara'), attempted, success, json.dumps(evidence)))
                db.execute('INSERT INTO events(time,path,kind,detail,run_id) VALUES(?,?,?,?,?)',
                           (time.time(), key, result, json.dumps(evidence), run_id))
                db.commit()
            count(result)
        # Persisted file attempts form the queue. Back off failures, and only
        # request a continuation when actual eligible work remains.
        summary['work_remaining'] = False
        if not dry and not discover_only:
            for path in pending_paths:
                if path.is_symlink() or not path.is_file():
                    continue
                row = db.execute('SELECT status,versions,last_attempt,stable_since,size,mtime FROM files WHERE path=?', (str(path),)).fetchone()
                st = path.stat()
                if row is None:
                    summary['work_remaining'] = True
                    break
                if row and (row[4], row[5]) == (st.st_size, st.st_mtime_ns) and now - row[3] >= cfg['stable_seconds']:
                    waiting = row[0] == 'SCAN_ERROR' and row[1] == fingerprint and time.time() - (row[2] or 0) < cfg.get('retry_seconds', 21600)
                    if not waiting and (row[0] == 'PENDING' or row[1] != fingerprint):
                        summary['work_remaining'] = True
                        break
        if not dry:
            db.execute('DELETE FROM events WHERE time < ?', (now - cfg['retention_days'] * 86400,))
            db.commit()
    finally:
        db.close()
    return summary



def reconcile_runs(db):
    """Called only while owning the scanner lock."""
    db.execute("""UPDATE runs SET state='interrupted', ended_at=updated_at,
        duration_seconds=MAX(0,updated_at-started_at),
        failure_reason='Scanner exited without finalizing; end time is last recorded progress'
        WHERE state='running'""")
    db.commit()


def scan(cfg, dry=False, target=None, discover_only=False):
    db = database(cfg['state_db'])
    reconcile_runs(db)
    started, clock = time.time(), time.monotonic()
    summary = {'counts': {}, 'visited': 0, 'scan_attempts': 0,
               'engine_attempts': {'clam': 0, 'yara': 0}, 'cached': 0,
               'discovery_truncated': False, 'dry_run': dry,
               'limits': {'max_files': cfg.get('max_files_per_run'), 'max_runtime_seconds': cfg.get('max_runtime_seconds')}}
    cursor = db.execute("""INSERT INTO runs(action,scope,dry_run,started_at,updated_at,state,summary)
        VALUES(?,?,?,?,?,'running',?)""", ('discover' if discover_only else 'scan',
        json.dumps([target] if target else [str(Path(cfg['mount']) / r) for r in cfg['roots']]),
        int(dry), started, started, json.dumps(summary)))
    run_id = cursor.lastrowid
    db.commit()

    def progress(value):
        summary.update(value)
        db.execute('UPDATE runs SET updated_at=?,duration_seconds=?,summary=? WHERE id=?',
                   (time.time(), time.monotonic()-clock, json.dumps(summary), run_id))
        db.commit()

    state, reason = 'completed', None
    try:
        summary.update(_scan(cfg, dry, target, discover_only, run_id, progress))
        if not discover_only and summary['counts'].get('SCAN_ERROR'):
            state, reason = 'failed', 'One or more files had scan errors'
        return dict(summary, run_id=run_id)
    except BaseException as exc:
        state = 'interrupted' if isinstance(exc, (KeyboardInterrupt, SystemExit, InterruptedError)) else 'failed'
        reason = str(exc) or type(exc).__name__
        raise
    finally:
        ended = time.time()
        db.execute("""UPDATE runs SET ended_at=?,updated_at=?,duration_seconds=?,state=?,
            failure_reason=?,summary=? WHERE id=?""",
            (ended, ended, time.monotonic()-clock, state, reason, json.dumps(summary), run_id))
        cutoff = ended - cfg['retention_days'] * 86400
        db.execute('DELETE FROM events WHERE time < ?', (cutoff,))
        db.execute("DELETE FROM runs WHERE started_at < ? AND state != 'running'", (cutoff,))
        db.commit()
        db.close()


def interrupted(signum, frame):
    # KeyboardInterrupt is not caught as an engine OSError inside scan_fd.
    raise KeyboardInterrupt('Scanner received termination signal')


def main():
    signal.signal(signal.SIGTERM, interrupted)
    p = argparse.ArgumentParser()
    p.add_argument('--config', default='/etc/four-security/scanner.json')
    p.add_argument('action', choices=('scan', 'discover', 'status', 'health', 'alerts'))
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--target')
    a = p.parse_args()
    try:
        cfg = json.loads(Path(a.config).read_text())
        if a.action in ('scan', 'discover'):
            with open(cfg['lock_file'], 'a') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError('SCAN_ERROR: another scan is running')
                result = scan(cfg, a.dry_run, a.target, a.action == 'discover')
            print(json.dumps(result, indent=2))
            counts = result['counts']
            return 2 if counts.get('SCAN_ERROR') and a.action == 'scan' else 1 if counts.get('MALWARE_DETECTED') or counts.get('YARA_MATCH') or counts.get('POLICY_VIOLATION') else 0
        if a.action == 'health':
            m = verify_mount(cfg)
            v, _ = engine_versions(cfg)
            print(json.dumps({'mount': m, 'engines': v, 'time': time.time()}, indent=2))
        else:
            db = database(cfg['state_db'])
            db.row_factory = sqlite3.Row
            if a.action == 'status':
                data = [dict(r) for r in db.execute('SELECT status,COUNT(*) AS files FROM files GROUP BY status')]
            else:
                data = [dict(r) for r in db.execute("SELECT * FROM events WHERE kind IN ('MALWARE_DETECTED','YARA_MATCH','SCAN_ERROR','PARTIALLY_SCANNED','SKIPPED_SIZE_LIMIT','FILE_CHANGED','POLICY_VIOLATION') ORDER BY id DESC LIMIT 100")]
            print(json.dumps(data, indent=2))
            db.close()
        return 0
    except Exception as e:
        print(json.dumps({'status': 'SCAN_ERROR', 'reason': str(e)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
