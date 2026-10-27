"""Tune a stock Suricata 8 config for this verified Pi; run once during staging."""
import sys
from pathlib import Path
import yaml

p = Path(sys.argv[1])
c = yaml.safe_load(p.read_text())
c['vars']['address-groups']['HOME_NET'] = (
    '[192.168.4.0/22,fd8a:a0e8:94f6:1::/64,2600:2b00:823e:e600::/64,fe80::/10]')
c['vars']['address-groups']['EXTERNAL_NET'] = '!$HOME_NET'
c['runmode'] = 'workers'
c['af-packet'] = [{'interface': 'eth0', 'threads': 1, 'cluster-id': 98,
                   'cluster-type': 'cluster_flow', 'defrag': True,
                   'use-mmap': True, 'tpacket-v3': True, 'ring-size': 8192}]
c['max-pending-packets'] = 1024
c['detect']['sgh-mpm-caching'] = True
c['detect']['sgh-mpm-caching-path'] = '/var/lib/suricata/cache/sgh'
c['detect']['sgh-mpm-caching-max-age'] = '7d'
c['flow']['memcap'] = '32mb'
c['stream']['memcap'] = '32mb'
c['stream']['reassembly']['memcap'] = '64mb'
c['default-rule-path'] = '/var/lib/suricata/rules'
c['rule-files'] = ['suricata.rules', '/etc/suricata/local.rules']
c['default-log-dir'] = '/var/log/suricata'
c['classification-file'] = '/etc/suricata/classification.config'
c['reference-config-file'] = '/etc/suricata/reference.config'
c['threshold-file'] = '/etc/suricata/threshold.config'
c['unix-command'] = {'enabled': False}
c.pop('run-as', None)
c['stats'] = {'enabled': True, 'interval': 30}
c['outputs'] = [
    {'fast': {'enabled': True, 'filename': 'fast.log', 'append': True}},
    {'eve-log': {'enabled': True, 'filetype': 'regular', 'filename': 'eve.json',
                 'types': ['alert', {'stats': {'totals': True, 'threads': False}},
                           'dns', 'tls', 'http']}},
]
c['logging'] = {'default-log-level': 'notice', 'outputs': [{'console': {'enabled': True}}]}
p.write_text('%YAML 1.1\n---\n' + yaml.safe_dump(c, sort_keys=False))
