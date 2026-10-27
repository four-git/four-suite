#!/usr/bin/env python3
"""Incrementally collect sanitized IDS alerts. No network delivery or blocking."""
import argparse
from collections import Counter
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def alert_record(event):
    a = event['alert']
    sid = int(a['signature_id'])
    def port(key):
        v = event.get(key)
        return v if isinstance(v, int) and 0 <= v <= 65535 else None
    record = {'time': stamp(event['timestamp']), 'sid': sid,
              'severity': max(1, min(3, int(a.get('severity', 3)))),
              'signature': str(a['signature'])[:240],
              'category': str(a.get('category', ''))[:160],
              'src_ip': str(event.get('src_ip', 'Layer 2'))[:45],
              'dest_ip': str(event.get('dest_ip', 'Layer 2'))[:45],
              'src_port': port('src_port'), 'dest_port': port('dest_port'),
              'proto': str(event.get('proto', 'Ethernet'))[:16],
              'test': sid == 1000001}
    record['id'] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    return record


def sensor_state():
    try:
        r = subprocess.run(['docker', 'inspect', 'four-ids-poc'], check=True,
                           capture_output=True, text=True, timeout=5)
        c = json.loads(r.stdout)[0]
        s = c['State']
        return {'running': bool(s['Running']), 'started_at': stamp(s['StartedAt']),
                'oom_killed': bool(s.get('OOMKilled')), 'restarts': c['RestartCount']}
    except (subprocess.SubprocessError, ValueError, KeyError, IndexError):
        return {'running': False, 'unavailable': True}


def collect(log_dir, state_dir, sensor, now=None, budget=8):
    now = time.time() if now is None else now
    state_dir.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(state_dir / 'alerts.sqlite3')
    db.execute('CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,time REAL,test INTEGER,body TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS cursors(id TEXT PRIMARY KEY,offset INTEGER,complete INTEGER,touched REAL)')
    db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)')
    errors, backlog = [], False
    deadline = time.monotonic() + budget
    files = sorted(log_dir.glob('eve.json*'), key=lambda p: (p.name != 'eve.json', p.name))
    for p in files:
        if time.monotonic() >= deadline:
            backlog = True
            break
        if p.is_symlink() or not p.is_file():
            continue
        try:
            st = p.stat()
            with p.open('rb') as raw:
                prefix = hashlib.sha256(raw.read(256)).hexdigest()
            key = f'{st.st_dev}:{st.st_ino}:{prefix}'
            cursor = db.execute('SELECT offset,complete FROM cursors WHERE id=?', (key,)).fetchone()
            offset = cursor[0] if cursor else 0
            compressed = p.suffix == '.gz'
            if compressed and cursor and cursor[1]:
                continue
            if not compressed and offset > st.st_size:
                offset = 0
            complete = False
            with (gzip.open(p, 'rb') if compressed else p.open('rb')) as stream:
                stream.seek(offset)
                while time.monotonic() < deadline:
                    before = stream.tell()
                    line = stream.readline(1024 * 1024)
                    if not line:
                        complete = True
                        break
                    if not line.endswith(b'\n') and len(line) < 1024 * 1024:
                        stream.seek(before)  # Retry a partially written event next time.
                        break
                    offset = stream.tell()
                    try:
                        e = json.loads(line)
                        when = stamp(e['timestamp'])
                        if when > now + 300:
                            raise ValueError('future event')
                        if e.get('event_type') == 'alert' and when >= now - 7 * 86400:
                            a = alert_record(e)
                            db.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?)',
                                       (a['id'], a['time'], a['test'], json.dumps(a)))
                        elif e.get('event_type') == 'stats':
                            prior = db.execute("SELECT value FROM meta WHERE key='stats'").fetchone()
                            if prior is None or when >= json.loads(prior[0])['time']:
                                s = {'time': when, 'capture': e['stats'].get('capture', {}),
                                     'decoder_packets': e['stats'].get('decoder', {}).get('pkts', 0)}
                                db.execute("INSERT OR REPLACE INTO meta VALUES('stats',?)", (json.dumps(s),))
                    except (ValueError, KeyError, TypeError, UnicodeError):
                        if 'Malformed log events skipped' not in errors:
                            errors.append('Malformed log events skipped')
            if time.monotonic() >= deadline:
                backlog = True
            db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?,?)', (key, offset, complete, now))
        except FileNotFoundError:
            continue  # A rotation raced this read; the next pass follows the renamed file.
        except (OSError, EOFError) as exc:
            errors.append('Log read failed (' + type(exc).__name__ + ')')
    db.execute('DELETE FROM alerts WHERE time < ?', (now - 7 * 86400,))
    over = db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] > 20000
    if over:
        db.execute('DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY time DESC LIMIT 20000)')
        db.execute("INSERT OR REPLACE INTO meta VALUES('capped_at',?)", (str(now),))
    db.execute('DELETE FROM cursors WHERE id NOT IN (SELECT id FROM cursors ORDER BY touched DESC LIMIT 32)')
    db.commit()
    latest = db.execute("SELECT value FROM meta WHERE key='stats'").fetchone()
    stats = json.loads(latest[0]) if latest else None
    valid_stats = bool(stats and stats['time'] >= sensor.get('started_at', now) - 1
                       and 0 <= now - stats['time'] <= 120)
    if sensor.get('unavailable'):
        health = 'Unavailable'
    elif not sensor.get('running'):
        health = 'Stopped'
    elif valid_stats:
        health = 'Running'
    elif stats and stats['time'] >= sensor.get('started_at', now) - 1:
        health = 'No fresh sensor statistics'
    elif now - sensor.get('started_at', 0) < 900:
        health = 'Starting'
    else:
        health = 'No fresh sensor statistics'
    counts = Counter()
    for test, severity, sid, count in db.execute(
            "SELECT test,json_extract(body,'$.severity'),json_extract(body,'$.sid'),COUNT(*) FROM alerts WHERE time>=? GROUP BY 1,2,3",
            (now - 86400,)):
        if sid == 2200121:
            counts['decoder_history'] += count
            continue  # This exact decoder signature was deliberately disabled after POC tuning.
        counts['tests' if test else 'review'] += count
        if not test:
            counts['severity_' + str(severity)] += count
    recent = [json.loads(row[0]) for row in db.execute('SELECT body FROM alerts ORDER BY time DESC LIMIT 50')]
    for a in recent:
        a['suppressed_history'] = a['sid'] == 2200121
    capped = db.execute("SELECT value FROM meta WHERE key='capped_at'").fetchone()
    db.close()
    return {'schema_version': 1, 'generated_at': now, 'health': health, 'sensor': sensor,
            'stats': stats, 'stats_fresh': valid_stats, 'counts_24h': dict(counts),
            'recent_alerts': recent, 'backlog': backlog, 'errors': errors,
            'history_limited': bool(capped and now - float(capped[0]) < 7 * 86400),
            'retention_days': 7, 'retention_max_alerts': 20000,
            'scope': 'Pi eth0 traffic; NAS 192.168.4.46 TCP/445 transfers excluded. LAN-wide visibility is unverified.',
            'delivery': 'Dashboard only. No email or phone notifications. Passive alerts; traffic is not blocked.'}


def write_report(path, payload):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.ids-', delete=False) as f:
            temporary = Path(f.name)
            json.dump(payload, f, allow_nan=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o640)
        os.chown(temporary, 0, 983)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log-dir', type=Path, default=Path('/var/log/four-security/ids-poc'))
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/four-security/ids-dashboard'))
    args = parser.parse_args()
    payload = collect(args.log_dir, args.state_dir, sensor_state())
    write_report(args.state_dir / 'report.json', payload)
    print(json.dumps({'health': payload['health'], 'review_alerts_24h': payload['counts_24h'].get('review', 0)}))


if __name__ == '__main__':
    main()
