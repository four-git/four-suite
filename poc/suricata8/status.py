"""Read-only summary: sudo python3 status.py"""
import json
import subprocess
from collections import Counter
from pathlib import Path

subprocess.run(['docker', 'ps', '--filter', 'name=^/four-ids-poc$',
                '--format', '{{.Names}}: {{.Status}}'], check=True)
subprocess.run(['docker', 'stats', '--no-stream', 'four-ids-poc'], check=True)
p = Path('/var/log/four-security/ids-poc/eve.json')
counts = Counter()
stats = None
alerts = Counter()
if p.exists():
    with p.open() as stream:
        for line in stream:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            counts[e.get('event_type', 'unknown')] += 1
            if e.get('event_type') == 'stats':
                stats = {'timestamp': e['timestamp'], 'capture': e['stats'].get('capture'),
                         'decoder_packets': e['stats'].get('decoder', {}).get('pkts')}
            if e.get('event_type') == 'alert':
                a = e['alert']
                alerts[(a['signature_id'], a['signature'])] += 1
print('Current log event counts:', dict(counts))
print('Latest counters:', json.dumps(stats))
for (sid, signature), count in alerts.most_common(15):
    print(f'  {count} alerts | SID {sid} | {signature}')
stamp = Path('/var/lib/four-security/ids-poc/rules/last-success.txt')
print('Last validated rule update:', stamp.read_text().strip() if stamp.exists() else 'none')
