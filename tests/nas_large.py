"""Read-only >2 GB real NAS file validation; ClamAV must be recorded skipped."""
import importlib.util
import json
import os
from pathlib import Path
import time
spec = importlib.util.spec_from_file_location('scanner', '/opt/four-security/src/four_security.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
cfg = json.loads(Path('/etc/four-security/scanner.json').read_text())
s.verify_mount(cfg)
paths = (p for p in (Path(cfg['mount']) / 'media').rglob('*') if not p.is_symlink() and p.is_file())
choices = [p for p in paths if 2_000_000_000 < p.stat().st_size < cfg['yara_max_bytes']]
p = min(choices, key=lambda x: x.stat().st_size)
before = p.stat()
t = time.monotonic()
fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
try:
    engines, evidence = s.scan_fd(fd, before.st_size, cfg, t + 360)
finally:
    os.close(fd)
after = p.stat()
assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
result = {'bytes': before.st_size, 'engines': engines, 'status': s.combine(engines['clam'], engines['yara']),
          'evidence': evidence, 'elapsed_seconds': time.monotonic() - t, 'size_and_mtime_unchanged': True}
print(json.dumps(result, indent=2))
assert engines['clam'] == 'SKIPPED_SIZE_LIMIT' and engines['yara'] in ('CLEAN', 'YARA_MATCH'), result
