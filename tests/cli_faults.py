"""Actual CLI must fail closed on an incorrect SMB source."""
import json
from pathlib import Path
import subprocess
import tempfile
cfg = json.loads(Path('/etc/four-security/scanner.json').read_text())
with tempfile.TemporaryDirectory(prefix='four-mount-fault-') as d:
    cfg['source'] = '//192.168.4.46/not-the-authorized-share'
    file = Path(d, 'fault.json')
    file.write_text(json.dumps(cfg))
    r = subprocess.run(['/usr/local/bin/four-security', '--config', str(file), 'health'], capture_output=True, text=True)
    assert r.returncode == 2 and 'SCAN_ERROR' in r.stderr, (r.returncode, r.stdout, r.stderr)
    print('PASS: wrong mount source fails closed with SCAN_ERROR / exit2')
