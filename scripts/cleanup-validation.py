"""Remove only this session's temporary access and local Pi test fixture."""
from pathlib import Path
authorized = Path('/root/.ssh/authorized_keys')
marker = 'codex-four-security-temporary'
lines = authorized.read_text().splitlines(keepends=True)
remaining = [line for line in lines if not (line.split() and line.split()[-1] == marker)]
authorized.write_text(''.join(remaining))
authorized.chmod(0o600)
fixture = Path('/var/lib/four-security/large-validation.bin')
if fixture.is_file() and fixture.stat().st_uid == 997 and 2_200_000_000 < fixture.stat().st_size < 2_200_001_000:
    fixture.unlink()
archive = Path('/tmp/four-security-phase3.tar.gz')
if archive.is_file():
    archive.unlink()
assert marker not in authorized.read_text()
print('Removed temporary setup SSH authorization and local validation artifacts. NAS untouched.')
