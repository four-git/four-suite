#!/usr/bin/env python3
"""Publish read-only SQLite reports to a separately mounted CIFS directory."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from reports import Reports


def normalized_source(source):
    # findmnt can display a CIFS prefixpath as //host/share[/subdirectory].
    if '[' in source and source.endswith(']'):
        base, suffix = source[:-1].split('[', 1)
        return base.rstrip('/') + '/' + suffix.lstrip('/')
    return source.rstrip('/')


def verify_destination(cfg):
    mount = Path(cfg['mount'])
    if not mount.is_absolute() or mount.is_symlink() or mount.resolve() != mount:
        raise ValueError('Report mount must be an absolute, non-symlink path')
    source = cfg['source']
    if not source.startswith('//') or 'REPLACE' in source:
        raise ValueError('Configure the verified report SMB source')
    name = cfg.get('output_name', 'status.json')
    if name != 'status.json':
        raise ValueError('output_name must be status.json')
    # Trigger an automount, but never treat an unmounted local directory as output.
    with os.scandir(mount):
        pass
    result = subprocess.run(['findmnt', '-J', '-T', str(mount), '-o', 'SOURCE,TARGET,FSTYPE,OPTIONS'],
                            capture_output=True, text=True, check=True, timeout=10)
    rows = json.loads(result.stdout)['filesystems']
    backing = [row for row in rows if row['fstype'] != 'autofs']
    if len(backing) != 1:
        raise RuntimeError('Expected one mounted report filesystem')
    row = backing[0]
    options = row['options'].split(',')
    if (row['fstype'] != 'cifs' or normalized_source(row['source']) != normalized_source(source) or row['target'] != str(mount)
            or 'rw' not in options or 'ro' in options):
        raise RuntimeError('Report source, target, or writable CIFS options do not match')
    output = mount / name
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError('Refusing non-regular report output')
    return output


def atomic_publish(output, payload):
    """Same-directory rename: readers see an old or new complete JSON document."""
    data = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         prefix='.four-security-', suffix='.tmp',
                                         dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o640)
        # Recheck immediately before replacement; no following a hostile destination link.
        if output.is_symlink():
            raise RuntimeError('Refusing symlink report output')
        os.replace(temporary, output)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def publish(cfg):
    scanner_path = Path(cfg['scanner_config'])
    scanner = json.loads(scanner_path.read_text(encoding='utf-8'))
    # Finish and close the local DB transaction before touching the network mount.
    payload = Reports(scanner).snapshot(cfg.get('recent_runs', 20))
    if cfg.get('ids_report'):
        try:
            ids = json.loads(Path(cfg['ids_report']).read_text(encoding='utf-8'))
            if ids.get('schema_version') != 1 or not isinstance(ids.get('recent_alerts'), list):
                raise ValueError('Invalid IDS snapshot')
            payload['ids'] = ids
        except (OSError, ValueError, TypeError, AttributeError):
            # IDS failure must not stop publication of valid file-scanner results.
            payload['ids'] = {'schema_version': 1, 'health': 'Report unavailable',
                              'generated_at': 0, 'recent_alerts': [], 'counts_24h': {}}
    output = verify_destination(cfg)
    atomic_publish(output, payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/four-security/publisher.json')
    args = parser.parse_args()
    try:
        cfg = json.loads(Path(args.config).read_text(encoding='utf-8'))
        payload = publish(cfg)
        print(json.dumps({'published_at': payload['generated_at'], 'schema_version': 1}))
        return 0
    except Exception as exc:
        # Avoid dumping configs, paths, SMB credentials or scan evidence to logs.
        print('Report publication failed (' + type(exc).__name__ + '); check configuration, database and report mount.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
