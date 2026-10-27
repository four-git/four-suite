"""Local full-file YARA-X adapter; the caller owns timeout and inherited FD."""
import argparse
import importlib.metadata
import json
from pathlib import Path
import sys


def main():
    sys.path.insert(0, '/opt/yara-x')
    import yara_x
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='store_true')
    parser.add_argument('--timeout', type=int, default=1200)
    parser.add_argument('--rules')
    parser.add_argument('path', nargs='?')
    args = parser.parse_args()
    if args.version:
        print('YARA-X ' + importlib.metadata.version('yara-x'))
        return 0
    if not args.rules or not args.path:
        parser.error('rules and an inherited file path are required')
    scanner = yara_x.Scanner(yara_x.compile(Path(args.rules).read_text()))
    scanner.set_timeout(args.timeout)
    # YARA-X otherwise stops recording a pattern after its match cap, which
    # could hide a late valid PE header in a very large file. Let the existing
    # process/container time and memory limits fail explicitly instead.
    scanner.max_matches_per_pattern(sys.maxsize)
    result = scanner.scan_file(args.path)
    matches = [rule.identifier for rule in result.matching_rules]
    if matches:
        print(json.dumps({'matching_rules': matches}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        sys.exit(2)
