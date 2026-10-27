"""Exercise actual triage rules using non-executable sparse media fixtures."""
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import time
p = Path('/var/lib/four-security/large-validation.bin')
rules = '/opt/four-security/rules/media-payload-indicators.yar'
results = {}
def fixture(tail):
    with p.open('wb') as f:
        f.write(bytes.fromhex('1a45dfa3'))
        f.seek(2_200_000_000)
        f.write(tail)
    os.chmod(p, 0o440)

def check(name, expect):
    t = time.monotonic()
    r = subprocess.run(['yara', '--print-meta', '--timeout=200', rules, str(p)],
                       capture_output=True, text=True, timeout=210)
    results[name] = {'bytes': p.stat().st_size, 'exit': r.returncode, 'output': r.stdout,
                     'stderr': r.stderr, 'elapsed_seconds': time.monotonic() - t}
    assert r.returncode == 0 and bool(r.stdout.strip()) == expect, results

# All fixture bytes are benign. Header shapes and literal strings are never executed.
os.chmod(p, 0o640)
pe = bytearray(68)
pe[:2] = b'MZ'
struct.pack_into('<I', pe, 60, 64)
pe[64:] = b'PE\0\0'
fixture(pe)
check('embedded_executable_header_after_2GB', True)
os.chmod(p, 0o640)
fixture(b'harmless large media fixture')
check('benign_large_media', False)
os.chmod(p, 0o640)
fixture(b'Literal indicators only: WScript.Shell ADODB.Stream MSXML2.XMLHTTP')
check('script_indicators_after_2GB', True)
results['peak_child_rss_kib'] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(json.dumps(results, indent=2))
