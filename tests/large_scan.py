import json
import resource
import subprocess
import time
t = time.monotonic()
r = subprocess.run(['yara', '--timeout=150', '/opt/four-security/rules/test-rule.yar',
                    '/var/lib/four-security/large-validation.bin'], capture_output=True, text=True, timeout=160)
print(json.dumps({'exit': r.returncode, 'output': r.stdout, 'stderr': r.stderr,
                  'elapsed_seconds': time.monotonic() - t,
                  'peak_child_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}, indent=2))
assert r.returncode == 0 and 'four_security_benign_test' in r.stdout
