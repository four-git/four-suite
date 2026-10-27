#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
dry_run=0
case "${1:-}" in
  --dry-run) [[ $# == 1 ]] || exit 2; dry_run=1 ;;
  '') ;;
  *) echo 'Usage: sudo bash scripts/install-suite.sh [--dry-run]' >&2; exit 2 ;;
esac
log() { printf '\n[install] %s\n' "$*"; }
die() { echo "[BLOCKED] $*" >&2; exit 2; }
trap 'echo "[BLOCKED] Build/install failed at line $LINENO; services were not started." >&2' ERR
[[ $EUID == 0 ]] || die 'Run with sudo on the Pi.'
[[ -f /etc/os-release ]] || die 'Debian 13 ARM64 required.'
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(uname -m) == aarch64 && $(dpkg --print-architecture) == arm64 ]] || die 'Debian 13 ARM64 required.'
# Existing legacy installations must use the journaled rename migration first.
if [[ -d /etc/four-securitycenter && ! -f /opt/four-security/.migration-snapshot ]]; then
  die 'Legacy configuration exists. Follow docs/DEPLOYMENT.md and run the rename migrator first.'
fi
log 'Check host prerequisites, config, native jobs and the read-only NAS mount'
for command in docker python3 timeout findmnt setpriv; do
  command -v "$command" >/dev/null || die 'Run scripts/pre-req.sh first.'
done
docker compose version
docker info >/dev/null
[[ -z $(docker ps --filter label=com.docker.compose.project=four-security --format '{{.Names}}') ]] || die 'Stop the suite before building; use suite update for a backed-up update.'
account=$(getent passwd 997 || true)
IFS=: read -r account_name _ _ account_gid _ <<< "$account"
[[ $account_gid == 983 && ( $account_name == scanner || $account_name == four-security ) ]] || die 'Run scripts/pre-req.sh to provision the compatible UID 997 / GID 983 identity.'
for directory in /var/lib/four-security /var/lib/clamav; do
  [[ -d $directory && ! -L $directory && $(stat -c %u:%g "$directory") == 997:983 ]] || die "Run scripts/pre-req.sh; review ownership of $directory."
done
python3 suite check
timeout --kill-after=5s 30s setpriv --reuid=997 --regid=983 --clear-groups python3 - <<'PY'
import json
import os
from pathlib import Path
cfg = json.loads(Path('/etc/four-security/scanner.json').read_text())
expected = {'mount': '/mnt/four-security/downloads', 'source': '//192.168.4.46/data',
            'state_db': '/var/lib/four-security/scans.sqlite3',
            'lock_file': '/var/lib/four-security/scan.lock',
            'rules': '/opt/four-security/rules/media-payload-indicators.yar',
            'clam_database': '/var/lib/clamav'}
for key, value in expected.items():
    if cfg.get(key) != value:
        raise SystemExit('Config must match Compose: ' + key + ' = ' + value)
for path in (cfg['mount'] + '/media', cfg['mount'] + '/torrents/complete'):
    if not os.access(path, os.R_OK | os.X_OK):
        raise SystemExit('Scanner cannot read/traverse ' + path)
for path in ('/var/lib/four-security', '/var/lib/clamav'):
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        raise SystemExit('Scanner cannot write ' + path)
PY
# Validate Compose even on first install, before a digest or .env exists.
if [[ -e .env ]]; then
  docker compose config --quiet
else
  DEBIAN_IMAGE=debian:13-slim SUITE_IMAGE=four-security:local docker compose config --quiet
fi
if (( dry_run )); then
  log 'Checks passed; no changes made. A real install will:'
  echo '  1. Resolve and record the Debian ARM64 digest if .env is absent.'
  echo '  2. Build the image and record its package versions and immutable image ID.'
  echo '  3. Keep existing config, credentials, data and schedule settings; start no services.'
  echo 'Run: sudo bash scripts/install-suite.sh'
  exit 0
fi
if [[ ! -e .env ]]; then
  log 'Resolve the Debian 13 ARM64 base image digest'
  docker pull --platform linux/arm64 debian:13-slim
  digest=$(docker image inspect debian:13-slim --format '{{index .RepoDigests 0}}')
  [[ $digest == debian@sha256:* ]] || die 'No registry image digest found.'
  umask 077
  printf 'DEBIAN_IMAGE=%s\nSCAN_INTERVAL_SECONDS=0\nDISCOVER_INTERVAL_SECONDS=0\n' "$digest" > .env
fi
log 'Build scanner, FreshClam and optional IDS into the shared ARM64 image'
SUITE_IMAGE=four-security:local docker compose build scanner
image=$(docker image inspect four-security:local --format '{{.Id}}')
[[ $(docker image inspect "$image" --format '{{.Architecture}}') == arm64 ]] || die 'Built image is not ARM64.'
log 'Record package versions and pin all services to the built image ID'
docker run --rm --network none --entrypoint cat "$image" /usr/local/share/package-versions.txt > package-versions.txt
python3 - "$image" <<'PY'
import json, pathlib, sys
env = pathlib.Path('.env')
lines = [line for line in env.read_text().splitlines() if not line.startswith('SUITE_IMAGE=')]
lines.append('SUITE_IMAGE=' + sys.argv[1])
env.write_text('\n'.join(lines) + '\n')
env.chmod(0o600)
data = json.loads(pathlib.Path('deployment-manifest.json').read_text())
base = next(line.split('=', 1)[1] for line in lines if line.startswith('DEBIAN_IMAGE='))
data.update(image_id=sys.argv[1], base_image=base,
            package_versions=pathlib.Path('package-versions.txt').read_text(),
            build_status='built on ARM64; live acceptance pending')
pathlib.Path('deployment-manifest.json').write_text(json.dumps(data, indent=2) + '\n')
PY
chmod +x suite scripts/*.sh
docker compose config --quiet
log 'Build complete. No containers or scans started.'
echo 'Next: sudo ./suite start; sudo ./suite logs; sudo ./suite doctor'
