"""Build-time ARM64 dependency from the official PyPI release, pinned by SHA256."""
import hashlib
import io
from pathlib import Path
import platform
import urllib.request
import zipfile

URL = 'https://files.pythonhosted.org/packages/bb/71/bfc58b9d8afbc2e25a1fd0ce72a69c48fc9cb554238cde33c89787d84ff2/yara_x-1.22.0-cp39-abi3-manylinux_2_28_aarch64.whl'
SHA256 = '066e86533b7143ee96bb80e36b683eb25dad8bc4c064603802d3a8cbbd97f03e'

if __name__ == '__main__':
    if platform.machine() != 'aarch64':
        raise SystemExit('This pinned dependency targets the ARM64 Pi image')
    with urllib.request.urlopen(URL, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit('YARA-X package checksum mismatch')
    target = Path('/opt/yara-x')
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            if not (target / entry.filename).resolve().is_relative_to(target):
                raise SystemExit('Unsafe dependency archive path')
        archive.extractall(target)
