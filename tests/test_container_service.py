import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('container_service', Path(__file__).parents[1] / 'src/container_service.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class ContainerTests(unittest.TestCase):
    def test_missing_and_stale_signatures_block(self):
        with tempfile.TemporaryDirectory() as directory:
            daily = Path(directory) / 'daily.cvd'
            with patch.object(s.Path, 'glob', return_value=[]):
                with self.assertRaises(RuntimeError):
                    s.signature_health()
            daily.write_text('fixture')
            with patch.object(s.Path, 'glob', return_value=[daily]):
                s.signature_health()
                with patch.object(s.time, 'time', return_value=daily.stat().st_mtime + 73 * 3600):
                    with self.assertRaises(RuntimeError):
                        s.signature_health()

    def test_short_schedule_rejected(self):
        with patch.dict(s.os.environ, {'SCAN_INTERVAL_SECONDS': '1'}):
            with self.assertRaises(ValueError):
                s.scheduler()

    def test_schedules_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(s, 'CONFIG', str(Path(directory) / 'missing.json')), \
                patch.dict(s.os.environ, {}, clear=True), patch.object(s, 'run') as run:
            s.stopping = True
            try:
                self.assertEqual(s.scheduler(), 0)
                run.assert_not_called()
            finally:
                s.stopping = False

    def test_termination_forwards_to_engine_group(self):
        from unittest.mock import Mock
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(s, 'child', process), patch.object(s.os, 'killpg', create=True) as kill:
            try:
                s.terminate(15, None)
                self.assertTrue(s.stopping)
                kill.assert_called_once_with(123, s.signal.SIGTERM)
            finally:
                s.stopping = False

    def test_queue_continues_before_six_hour_interval(self):
        self.check_schedule('{"work_remaining": true}', None, [30, 60])

    def test_nas_outage_retries_after_five_minutes(self):
        self.check_schedule('{}', '[Errno 112] Host is down', [30, 330])

    def check_schedule(self, summary, failure, expected):
        import json
        import sqlite3
        with tempfile.TemporaryDirectory() as directory:
            cfg = Path(directory) / 'scanner.json'
            state = Path(directory) / 'state.sqlite3'
            cfg.write_text(json.dumps({'state_db': str(state), 'scan_on_startup': True,
                                       'continuation_seconds': 30}))
            with sqlite3.connect(state) as db:
                db.execute('CREATE TABLE runs(id INTEGER, action TEXT, dry_run INTEGER, summary TEXT, failure_reason TEXT)')
                db.execute('INSERT INTO runs VALUES(1,?,?,?,?)', ('scan', 0, summary, failure))
            clock, starts = [0], []
            def sleep(seconds):
                clock[0] += seconds
            def run(args):
                starts.append(clock[0])
                if len(starts) == 2:
                    s.stopping = True
                return 0
            try:
                with patch.object(s, 'CONFIG', str(cfg)), patch.object(s, 'daemon', None), \
                     patch.object(s, 'run', side_effect=run), \
                     patch.object(s.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(s.time, 'sleep', side_effect=sleep), \
                     patch.dict(s.os.environ, {'SCAN_INTERVAL_SECONDS': '21600', 'DISCOVER_INTERVAL_SECONDS': '0'}):
                    s.scheduler()
                self.assertEqual(starts, expected)
            finally:
                s.stopping = False


if __name__ == '__main__':
    unittest.main()
