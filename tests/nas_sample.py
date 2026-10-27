"""Read one existing media file, using a temporary 500 MB acceptance cap."""
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
cfg['clam_max_bytes'] = 500_000_000
cfg['clam_scan_bytes'] = 1_000_000_000
cfg['engine_timeout'] = 360
cfg['clam_scan_time_ms'] = 240000
p = Path('/mnt/four-security/downloads/media/tv/Curb Your Enthusiasm/Season 1/Curb.Your.Enthusiasm.S01E07.1080p.WEBRip.x265-RARBG.mp4')
before = p.stat()
fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
t = time.monotonic()
try:
    engines, evidence = s.scan_fd(fd, before.st_size, cfg, t + 390)
finally:
    os.close(fd)
after = p.stat()
assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
print(json.dumps({'bytes': before.st_size, 'engines': engines, 'evidence': evidence,
                  'status': s.combine(engines['clam'], engines['yara']),
                  'size_and_mtime_unchanged': True, 'elapsed_seconds': time.monotonic() - t}, indent=2))
assert engines['clam'] == 'CLEAN'
