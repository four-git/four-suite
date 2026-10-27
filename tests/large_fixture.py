"""Create a sparse, harmless local-only 2.2 GB validation fixture."""
import os
from pathlib import Path
p = Path('/var/lib/four-security/large-validation.bin')
with p.open('xb') as f:
    f.seek(2_200_000_000)
    f.write(b'FOUR_SECURITY_YARA_TEST_SAMPLE')
os.chown(p, 997, 983)
os.chmod(p, 0o440)
print('Harmless local sparse fixture bytes:', p.stat().st_size)
