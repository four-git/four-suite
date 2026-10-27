"""Run inside the ARM64 image, with /rules mounted read-only."""
import os
import sys
import time

sys.path.insert(0, '/opt/four-security/src')
from four_security import scan_fd

cfg = dict(clam_max_bytes=1, clam_scan_bytes=1, yara_max_bytes=0,
           engine_timeout=1200, rules='/rules/media-payload-indicators.yar', yara_mode='yara-x')
header = bytes.fromhex('1a45dfa3')
pe = bytearray(256)
pe[:2] = b'MZ'
pe[60:64] = (128).to_bytes(4, 'little')
pe[128:132] = b'PE' + bytes(2)
for label, data, expected in (
    ('clean', header + b'video data', 'CLEAN'),
    ('embedded executable', header + bytes(pe), 'YARA_MATCH'),
    ('late executable beyond default match cap', header + b'MZ' * 1000001 + bytes(pe), 'YARA_MATCH'),
    ('script indicators', header + b'powershell.exe -EncodedCommand FromBase64String', 'YARA_MATCH'),
):
    fd = os.memfd_create('acceptance')
    try:
        os.write(fd, data)
        engines, evidence = scan_fd(fd, len(data), cfg, time.monotonic() + 120)
        assert engines == {'clam': 'SKIPPED_SIZE_LIMIT', 'yara': expected}, (label, engines, evidence)
        print(label + ': ' + expected, flush=True)
    finally:
        os.close(fd)
