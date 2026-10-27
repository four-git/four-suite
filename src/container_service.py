"""Container lifecycle. Scheduling is opt-in; the scanner owns the shared lock."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CONFIG = '/etc/four-security/scanner.json'
RUNNER = str(Path(__file__).with_name('four_security.py'))
stopping = False
child = None
daemon = None


def terminate(signum, frame):
    global stopping
    stopping = True
    if child is not None and child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)


def run(args):
    global child
    child = subprocess.Popen(args, start_new_session=True)
    try:
        while child.poll() is None:
            if stopping:
                try:
                    return child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
            time.sleep(0.2)
        return child.returncode
    finally:
        child.wait()
        child = None


def signature_health():
    daily = [p for p in Path('/var/lib/clamav').glob('daily.*') if p.suffix in ('.cvd', '.cld')]
    if not daily or time.time() - max(p.stat().st_mtime for p in daily) > 72 * 3600:
        raise RuntimeError('BLOCKED: missing or stale daily signatures')


def reconcile_startup():
    # Reconcile crash leftovers at startup without interfering with a manual scan.
    import fcntl
    from four_security import database, reconcile_runs
    cfg = json.loads(Path(CONFIG).read_text())
    with open(cfg['lock_file'], 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            db = database(cfg['state_db'])
            try:
                reconcile_runs(db)
            finally:
                db.close()


def scheduler():
    intervals = {action: int(os.environ.get(env, '0')) for action, env in (
        ('scan', 'SCAN_INTERVAL_SECONDS'), ('discover', 'DISCOVER_INTERVAL_SECONDS'))}
    if any(value < 0 or 0 < value < 60 for value in intervals.values()):
        raise ValueError('Intervals must be zero (disabled) or at least 60 seconds')
    due = {action: time.monotonic() + interval for action, interval in intervals.items()}
    cfg = json.loads(Path(CONFIG).read_text()) if Path(CONFIG).exists() else {}
    if intervals['scan'] and cfg.get('scan_on_startup'):
        due['scan'] = time.monotonic() + cfg.get('continuation_seconds', 30)
    print(json.dumps({'schedules': intervals, 'coverage': 'Narrow YARA triage; ClamAV file ceiling remains'}), flush=True)
    while not stopping:
        if daemon is not None and daemon.poll() is not None:
            raise RuntimeError('ClamAV daemon exited; scanner restart required')
        for action, interval in intervals.items():
            if stopping:
                break
            if interval and time.monotonic() >= due[action]:
                rc = run([sys.executable, RUNNER, '--config', CONFIG, action])
                print(json.dumps({'action': action, 'exit_code': rc}), flush=True)
                due[action] = time.monotonic() + interval
                if action == 'scan':
                    import sqlite3
                    cfg = json.loads(Path(CONFIG).read_text())
                    with sqlite3.connect(cfg['state_db']) as db:
                        row = db.execute("SELECT summary,failure_reason FROM runs WHERE action='scan' AND dry_run=0 ORDER BY id DESC LIMIT 1").fetchone()
                    if row and (json.loads(row[0]).get('work_remaining') or 'reloading signatures' in (row[1] or '')):
                        due[action] = time.monotonic() + cfg.get('continuation_seconds', 30)
                    elif row and row[1] and row[1] != 'One or more files had scan errors':
                        # A NAS reboot/mount outage or failed preflight must not
                        # strand the entire queue until the six-hour baseline.
                        due[action] = time.monotonic() + max(60, cfg.get('failure_retry_seconds', 300))
        time.sleep(1)
    return 0


def main():
    global daemon
    action = sys.argv[1] if len(sys.argv) > 1 else 'scheduler'
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    if action == 'scheduler':
        reconcile_startup()
        cfg = json.loads(Path(CONFIG).read_text())
        if cfg.get('clam_mode') != 'daemon':
            return scheduler()
        from four_security import clam_daemon
        config = '\n'.join([
            'Foreground yes', 'LocalSocket ' + cfg.get('clam_socket', '/tmp/four-security-clamd.sock'),
            'LocalSocketMode 0600', 'FixStaleSocket yes', 'PidFile /tmp/four-security-clamd.pid',
            'DatabaseDirectory ' + cfg['clam_database'], 'TemporaryDirectory /tmp',
            'MaxThreads 1', 'MaxQueue 2', 'ConcurrentDatabaseReload no', 'SelfCheck 30',
            'AlertExceedsMax yes', 'MaxFileSize ' + str(cfg['clam_max_bytes']),
            'MaxScanSize ' + str(cfg['clam_scan_bytes']),
            'MaxScanTime ' + str(cfg.get('clam_scan_time_ms', 600000)), 'LogTime yes',
        ]) + '\n'
        Path('/tmp/four-security-clamd.conf').write_text(config)
        daemon = subprocess.Popen(['clamd', '--config-file=/tmp/four-security-clamd.conf'], start_new_session=True)
        try:
            deadline = time.monotonic() + 240
            while not stopping:
                if daemon.poll() is not None:
                    raise RuntimeError('ClamAV daemon failed to start')
                try:
                    if clam_daemon(cfg, 'PING') == 'PONG':
                        break
                except (OSError, RuntimeError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError('ClamAV daemon startup timed out')
                time.sleep(1)
            return scheduler()
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
            daemon = None
    if action == 'signatures':
        return run(['freshclam', '--daemon', '--foreground=true', '--config-file=/etc/clamav/freshclam.conf'])
    if action == 'signature-health':
        signature_health()
        return 0
    if action == 'ids':
        interface = os.environ.get('CAPTURE_INTERFACE', '')
        if not interface or not Path('/sys/class/net', interface).is_dir():
            raise ValueError('Explicit, validated capture interface required')
        return run(['suricata', '-c', '/etc/suricata/suricata.yaml', '-i', interface])
    return run([sys.executable, RUNNER, '--config', CONFIG, *sys.argv[1:]])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc)}), file=sys.stderr)
        sys.exit(2)
