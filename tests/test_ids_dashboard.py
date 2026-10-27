import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))
from ids_dashboard import collect
import publish_reports


class IdsDashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.state = self.root / 'state'
        self.now = 1800000000
        self.sensor = {'running': True, 'started_at': self.now - 100}

    def event(self, kind='alert', age=10, sid=42):
        e = {'timestamp': datetime.fromtimestamp(self.now - age, timezone.utc).isoformat(), 'event_type': kind}
        if kind == 'alert':
            e.update({'alert': {'signature_id': sid, 'severity': 1, 'signature': '<img onerror=evil()>', 'category': 'test'},
                      'src_ip': '192.168.4.85', 'dest_ip': '192.168.4.51', 'proto': 'UDP',
                      'payload': 'DO NOT PUBLISH', 'http': {'url': 'PRIVATE'}, 'dest_port': 49098})
        else:
            e['stats'] = {'capture': {'kernel_packets': 100, 'kernel_drops': 0}, 'decoder': {'pkts': 100}}
        return json.dumps(e) + '\n'

    def snapshot(self, **kwargs):
        return collect(self.logs, self.state, kwargs.pop('sensor', self.sensor), now=self.now, **kwargs)

    def test_duplicate_rotation_and_gzip_are_counted_once(self):
        data = self.event() + self.event('stats')
        current = self.logs / 'eve.json'
        current.write_text(data)
        self.assertEqual(self.snapshot()['counts_24h']['review'], 1)
        current.rename(self.logs / 'eve.json.1')
        current.write_text(data + self.event(age=5, sid=43))
        with gzip.open(self.logs / 'eve.json.2.gz', 'wt') as f:
            f.write(data)
        for _ in range(2):
            r = self.snapshot()
            self.assertEqual(r['counts_24h']['review'], 2)
            self.assertEqual(r['health'], 'Running')
        self.assertNotIn('DO NOT PUBLISH', json.dumps(r))
        self.assertNotIn('PRIVATE', json.dumps(r))

    def test_partial_append_is_retried_and_tests_stay_separate(self):
        data = self.event(sid=1000001)
        p = self.logs / 'eve.json'
        p.write_text(data[:-10])
        self.assertEqual(self.snapshot()['recent_alerts'], [])
        with p.open('a') as f:
            f.write(data[-10:])
        r = self.snapshot()
        self.assertEqual(r['counts_24h']['tests'], 1)
        self.assertEqual(r['counts_24h'].get('review', 0), 0)
        # ET's diagnostic rule may also match real traffic: it remains reviewable.
        with p.open('a') as f:
            f.write(self.event(sid=2100498))
        self.assertEqual(self.snapshot()['counts_24h']['review'], 1)

    def test_stopped_stale_and_restarted_are_not_healthy(self):
        p = self.logs / 'eve.json'
        p.write_text(self.event('stats', age=130))
        old = {'running': True, 'started_at': self.now - 1000}
        self.assertEqual(self.snapshot(sensor=old)['health'], 'No fresh sensor statistics')
        p.write_text(self.event('stats', age=10))
        self.assertEqual(self.snapshot(sensor={'running': False})['health'], 'Stopped')
        r = self.snapshot(sensor={'running': True, 'started_at': self.now - 5})
        self.assertEqual(r['health'], 'Starting')
        self.assertFalse(r['stats_fresh'])

    def test_retention_and_malformed_records(self):
        (self.logs / 'eve.json').write_text('broken\n' + self.event(age=8*86400) + self.event(age=2*86400))
        r = self.snapshot()
        self.assertEqual(len(r['recent_alerts']), 1)
        self.assertEqual(r['counts_24h'].get('review', 0), 0)
        self.assertTrue(r['errors'])

    def test_backlog_is_explicit(self):
        (self.logs / 'eve.json').write_text(self.event())
        self.assertTrue(self.snapshot(budget=0)['backlog'])

    def test_only_deliberately_disabled_decoder_history_is_excluded(self):
        (self.logs / 'eve.json').write_text(self.event(sid=2200121) + self.event(sid=2200074))
        r = self.snapshot()
        self.assertEqual(r['counts_24h']['decoder_history'], 1)
        self.assertEqual(r['counts_24h']['review'], 1)
        self.assertTrue(next(a for a in r['recent_alerts'] if a['sid'] == 2200121)['suppressed_history'])

    def test_missing_ids_snapshot_does_not_prevent_scanner_publication(self):
        scanner = self.root / 'scanner.json'
        scanner.write_text('{}')
        cfg = {'scanner_config': str(scanner), 'ids_report': str(self.root / 'missing.json')}
        with patch.object(publish_reports, 'Reports') as reports, \
                patch.object(publish_reports, 'verify_destination', return_value=self.root / 'status.json'), \
                patch.object(publish_reports, 'atomic_publish') as publish:
            reports.return_value.snapshot.return_value = {'generated_at': self.now, 'findings': []}
            payload = publish_reports.publish(cfg)
        self.assertEqual(payload['ids']['health'], 'Report unavailable')
        self.assertEqual(payload['findings'], [])
        publish.assert_called_once()

    def test_optional_ids_snapshot_is_embedded_without_changing_scan_results(self):
        scanner = self.root / 'scanner.json'
        scanner.write_text('{}')
        ids = self.root / 'ids.json'
        ids.write_text(json.dumps(self.snapshot()))
        cfg = {'scanner_config': str(scanner), 'ids_report': str(ids)}
        with patch.object(publish_reports, 'Reports') as reports, \
                patch.object(publish_reports, 'verify_destination', return_value=self.root / 'status.json'), \
                patch.object(publish_reports, 'atomic_publish'):
            reports.return_value.snapshot.return_value = {'generated_at': self.now, 'findings': []}
            payload = publish_reports.publish(cfg)
        self.assertEqual(payload['ids']['health'], 'Starting')
        self.assertEqual(payload['findings'], [])


if __name__ == '__main__':
    unittest.main()
