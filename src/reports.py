"""Read-only scanner reporting queries. No network service or database mutations."""
import json
from pathlib import Path, PurePosixPath
import sqlite3
import time
from contextlib import contextmanager


class Reports:
    def __init__(self, cfg, lock_busy=None):
        self.cfg = cfg
        self.lock_busy = lock_busy or self.scanner_busy
        self.custom_lock_probe = lock_busy

    @contextmanager
    def snapshot_lock(self):
        """If idle, briefly hold a shared lock so a new scan cannot race projection."""
        if self.custom_lock_probe is not None:
            yield self.custom_lock_probe()
            return
        import fcntl
        try:
            lock = open(self.cfg['lock_file'], 'r')
        except FileNotFoundError:
            yield False
            return
        with lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                yield True
            else:
                yield False

    def scanner_busy(self):
        import fcntl
        try:
            with open(self.cfg['lock_file'], 'r') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return False
                except BlockingIOError:
                    return True
        except FileNotFoundError:
            return False

    def run(self, row, busy=None):
        if row is None:
            return None
        result = dict(row)
        result['scope'] = json.loads(result['scope'])
        result['summary'] = json.loads(result['summary'])
        result['dry_run'] = bool(result['dry_run'])
        if result['state'] == 'running':
            if self.lock_busy() if busy is None else busy:
                result['duration_seconds'] = max(0, time.time() - result['started_at'])
            else:
                result.update(state='interrupted', ended_at=result['updated_at'],
                              duration_seconds=max(0, result['updated_at']-result['started_at']),
                              failure_reason='Scanner stopped; end time is last recorded progress')
        return result

    def finding(self, row):
        result = dict(row)
        relative = None
        try:
            relative = PurePosixPath(result['path']).relative_to(PurePosixPath(self.cfg['mount']))
        except ValueError:
            pass
        result['share_path'] = (self.cfg['source'].rstrip('/') + '/' + str(relative)) if relative is not None else None
        result['label'] = 'Review required' if result['kind'] == 'YARA_MATCH' else result['kind']
        result['observation_note'] = 'Last observed result; file existence has not been rechecked'
        detail = result.pop('detail', None)
        try:
            result['evidence'] = json.loads(detail)
        except (ValueError, TypeError):
            result['evidence'] = detail
        return result

    def snapshot(self, recent_runs=20):
        """Materialize one consistent local snapshot; close SQLite before any SMB I/O."""
        with self.snapshot_lock() as busy:
            return self._snapshot(recent_runs, busy)

    def _snapshot(self, recent_runs, busy):
        if not isinstance(recent_runs, int) or isinstance(recent_runs, bool) or not 1 <= recent_runs <= 100:
            raise ValueError('recent_runs must be 1–100')
        now = time.time()
        cutoff = now - self.cfg.get('retention_days', 30) * 86400
        db = sqlite3.connect(Path(self.cfg['state_db']).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN')
            real = "action='scan' AND dry_run=0 AND started_at>=?"
            latest = self.run(db.execute(f'SELECT * FROM runs WHERE {real} ORDER BY id DESC LIMIT 1', (cutoff,)).fetchone(), busy)
            completed = self.run(db.execute(f"SELECT * FROM runs WHERE {real} AND state='completed' ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone(), busy)
            active = self.run(db.execute("SELECT * FROM runs WHERE state='running' ORDER BY id DESC LIMIT 1").fetchone(), busy)
            if active and active['state'] != 'running':
                active = None
            counts = dict(db.execute('SELECT status,COUNT(*) FROM files GROUP BY status'))
            findings = [self.finding(row) for row in db.execute('''
                SELECT path,status AS kind,reason AS detail,COALESCE(last_attempt,stable_since) AS time,clam,yara
                FROM files WHERE status IN ('MALWARE_DETECTED','YARA_MATCH','SCAN_ERROR',
                    'PARTIALLY_SCANNED','SKIPPED_SIZE_LIMIT','POLICY_VIOLATION') ORDER BY time DESC,path''')]
            findings.extend(self.finding(row) for row in db.execute('''
                SELECT e.path,e.kind,e.detail,e.time,e.run_id FROM events e JOIN files f ON f.path=e.path
                WHERE e.kind='FILE_CHANGED' AND f.status='PENDING' AND e.time>=f.stable_since
                AND e.id=(SELECT MAX(x.id) FROM events x WHERE x.path=e.path AND x.kind='FILE_CHANGED')'''))
            for row in db.execute('''SELECT path,'FILE_CHANGED' AS kind,reason AS detail,
                    COALESCE(last_attempt,stable_since) AS time,clam,yara
                    FROM files WHERE status='PENDING' AND reason LIKE '%file changed during scanning%' '''):
                item = self.finding(row)
                if isinstance(item['evidence'], dict) and item['evidence'].get('reason') == 'file changed during scanning':
                    findings.append(item)
            # A file may have both a metadata-change event and an in-scan change.
            # Keep its latest still-current warning rather than duplicate paths.
            unique = {}
            for item in findings:
                old = unique.get(item['path'])
                if old is None or (item['time'] or 0) > (old['time'] or 0):
                    unique[item['path']] = item
            findings = list(unique.values())
            priority = {'MALWARE_DETECTED': 0, 'YARA_MATCH': 1, 'SCAN_ERROR': 2, 'FILE_CHANGED': 3}
            findings.sort(key=lambda x: (priority.get(x['kind'], 4), -(x['time'] or 0), x['path']))
            return {
                'schema_version': 1, 'generated_at': now,
                'latest_scan': latest, 'latest_completed_scan': completed, 'active_run': active,
                'file_counts': counts,
                'recent_runs': [self.run(row, busy) for row in db.execute(f'SELECT * FROM runs WHERE {real} ORDER BY id DESC LIMIT ?', (cutoff, recent_runs))],
                'retained_scan_count': db.execute(f'SELECT COUNT(*) FROM runs WHERE {real}', (cutoff,)).fetchone()[0],
                'retention_days': self.cfg.get('retention_days', 30),
                'stale_scan_seconds': self.cfg.get('stale_scan_seconds', 86400),
                'findings': findings,
                'coverage_note': 'Bounded runs do not establish full-library coverage. Counts and findings are last recorded observations; file existence has not been rechecked. YARA matches require review.'
            }
        finally:
            db.close()

    def query(self, route, params):
        limit = int(params.get('limit', ['20'])[0])
        offset = int(params.get('offset', ['0'])[0])
        if not 1 <= limit <= 100 or offset < 0 or offset > 1000000:
            raise ValueError('Invalid pagination')
        db = sqlite3.connect(Path(self.cfg['state_db']).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        cutoff = time.time() - self.cfg.get('retention_days', 30)*86400
        try:
            # One read transaction gives each response a consistent view during scans.
            db.execute('BEGIN')
            if route == '/status':
                latest = db.execute("SELECT * FROM runs WHERE action='scan' AND dry_run=0 AND started_at>=? ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone()
                completed = db.execute("SELECT * FROM runs WHERE action='scan' AND dry_run=0 AND state='completed' AND started_at>=? ORDER BY id DESC LIMIT 1", (cutoff,)).fetchone()
                active = db.execute("SELECT * FROM runs WHERE state='running' ORDER BY id DESC LIMIT 1").fetchone()
                counts = dict(db.execute('SELECT status,COUNT(*) FROM files GROUP BY status').fetchall())
                reference = completed['ended_at'] if completed else None
                return {'version': 1, 'generated_at': time.time(), 'latest_scan': self.run(latest),
                        'latest_completed_scan': self.run(completed), 'active_run': self.run(active),
                        'file_counts': counts, 'stale': reference is None or time.time()-reference > self.cfg.get('stale_scan_seconds', 86400),
                        'coverage_note': 'Bounded runs do not establish full-library coverage. Counts are last recorded observations.'}
            if route == '/runs':
                total = db.execute('SELECT COUNT(*) FROM runs WHERE started_at>=?', (cutoff,)).fetchone()[0]
                rows = db.execute('SELECT * FROM runs WHERE started_at>=? ORDER BY id DESC LIMIT ? OFFSET ?', (cutoff, limit, offset))
                return {'version': 1, 'items': [self.run(r) for r in rows], 'total': total, 'limit': limit, 'offset': offset}
            if route.startswith('/runs/'):
                run_id = int(route.removeprefix('/runs/'))
                row = db.execute('SELECT * FROM runs WHERE id=? AND started_at>=?', (run_id, cutoff)).fetchone()
                if row is None:
                    return None
                events = db.execute('SELECT id,time,path,kind,detail,run_id FROM events WHERE run_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (run_id, limit, offset))
                total = db.execute('SELECT COUNT(*) FROM events WHERE run_id=?', (run_id,)).fetchone()[0]
                return {'version': 1, 'run': self.run(row), 'events': [self.finding(r) for r in events], 'total': total, 'limit': limit, 'offset': offset}
            if route == '/findings':
                mode = params.get('mode', ['current'])[0]
                kinds = "('MALWARE_DETECTED','YARA_MATCH','SCAN_ERROR','PARTIALLY_SCANNED','SKIPPED_SIZE_LIMIT','POLICY_VIOLATION')"
                if mode == 'current':
                    source = 'files WHERE status IN ' + kinds
                    fields = 'path,status AS kind,reason AS detail,COALESCE(last_attempt,stable_since) AS time,clam,yara'
                    order = 'time DESC,path'
                    args = ()
                elif mode == 'history':
                    source = 'events WHERE kind IN ' + kinds + ' AND time>=?'
                    fields = 'id,path,kind,detail,time,run_id'
                    order = 'id DESC'
                    args = (cutoff,)
                else:
                    raise ValueError('Invalid finding mode')
                total = db.execute('SELECT COUNT(*) FROM ' + source, args).fetchone()[0]
                rows = db.execute('SELECT ' + fields + ' FROM ' + source + ' ORDER BY ' + order + ' LIMIT ? OFFSET ?', (*args, limit, offset))
                return {'version': 1, 'mode': mode, 'items': [self.finding(r) for r in rows], 'total': total, 'limit': limit, 'offset': offset}
            return None
        finally:
            db.close()
