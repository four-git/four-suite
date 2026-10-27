"""Non-production local-fixture checks on the Pi, run as scanner user."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time

root = Path('/opt/four-security')
spec = importlib.util.spec_from_file_location('scanner', root / 'src/four_security.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
cfg = json.loads(Path('/etc/four-security/scanner.json').read_text())
cfg['rules'] = '/opt/four-security/rules/test-rule.yar'
with tempfile.TemporaryDirectory(prefix='four-security-test-') as d:
    d = Path(d)
    samples = {
        'eicar.txt': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        'yara.txt': b'FOUR_SECURITY_YARA_TEST_SAMPLE',
        'clean.txt': b'harmless local scanner acceptance fixture'
    }
    report = {}
    for name, content in samples.items():
        path = d / name
        path.write_bytes(content)
        fd = os.open(path, os.O_RDONLY)
        try:
            engines, evidence = s.scan_fd(fd, len(content), cfg, time.monotonic() + 180)
            report[name] = {'engines': engines, 'status': s.combine(engines['clam'], engines['yara']), 'evidence': evidence}
        finally:
            os.close(fd)
    assert report['eicar.txt']['status'] == 'MALWARE_DETECTED', report
    assert report['yara.txt']['status'] == 'YARA_MATCH', report
    assert report['clean.txt']['status'] == 'CLEAN', report
    print(json.dumps(report, indent=2))
