#!/usr/bin/env bash
# Host preparation only. Run on the Pi, never inside a container.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
dry_run=0
migrate=0
mount_only=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --migrate-native) migrate=1 ;;
    --mount) mount_only=1 ;;
    --help|-h)
      echo 'Usage: sudo bash scripts/pre-req.sh [--dry-run] [--migrate-native]'
      echo '       sudo bash scripts/pre-req.sh --mount [--dry-run]'
      echo 'Default: prepare host. --migrate-native: snapshot and stop native jobs before migration.'
      echo '--mount: mount and verify the NAS after you enter credentials with sudoedit.'
      exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done
log() { printf '\n[pre-req] %s\n' "$*"; }
die() { echo "[BLOCKED] $*" >&2; exit 2; }
run() {
  printf '  +'; printf ' %q' "$@"; printf '\n'
  if (( ! dry_run )); then "$@"; fi
}
trap 'echo "[BLOCKED] Failed at line $LINENO. Fix the reported error, then rerun the same command." >&2' ERR
[[ $EUID == 0 ]] || die 'Run with sudo on the Pi.'
[[ -f /etc/os-release ]] || die 'Debian 13 ARM64 is required.'
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(uname -m) == aarch64 && $(dpkg --print-architecture) == arm64 ]] || die 'Debian 13 / aarch64 / arm64 is required.'
(( ! mount_only || ! migrate )) || die '--mount and --migrate-native are separate steps.'
# Existing legacy installations must use the journaled rename migration first.
if [[ -d /etc/four-securitycenter && ! -f /opt/four-security/.migration-snapshot ]]; then
  die 'Legacy configuration exists. Follow docs/DEPLOYMENT.md and run the rename migrator first.'
fi
log "Host: $(hostname); Debian $VERSION_ID; ARM64. Dry-run=$dry_run"
df -h / /var
free -h

mount_path=/mnt/four-security/downloads
nas_source=//192.168.4.46/data
credentials=/etc/four-security/smb.credentials

if (( mount_only )); then
  log 'Mount and verify the existing NAS configuration (no package or ownership changes)'
  for command in systemd-escape findmnt python3 timeout setpriv; do
    command -v "$command" >/dev/null || die 'Run host preparation first.'
  done
  [[ -f $credentials && ! -L $credentials ]] || die "Create $credentials using host preparation first."
  [[ $(stat -c %u:%a "$credentials") == 0:600 ]] || die 'SMB credentials must be root-owned, mode 0600.'
  if grep -q 'CHANGE_ME' "$credentials" || ! grep -q '^username=.' "$credentials" || ! grep -q '^password=.' "$credentials"; then
    die "Enter the NAS read-only account using sudoedit $credentials, then rerun --mount."
  fi
  run systemctl daemon-reload
  # Access may trigger an existing systemd automount. Bound all network filesystem checks.
  if findmnt -rn -M "$mount_path" -t cifs >/dev/null; then
    log 'CIFS is already mounted; verify it without remounting'
  else
    # The fstab automount can activate during path lookup. Let its owner serialize
    # activation instead of racing mount.cifs against systemd's mount job.
    mount_unit=$(systemd-escape --path --suffix=mount "$mount_path")
    run timeout --kill-after=5s 30s systemctl start "$mount_unit"
  fi
  if (( ! dry_run )); then
    timeout --kill-after=5s 30s python3 - "$PWD/src" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from four_security import verify_mount
verify_mount({'mount': '/mnt/four-security/downloads', 'source': '//192.168.4.46/data',
              'expected_dirs': ['media', 'torrents/complete']})
PY
    timeout --kill-after=5s 30s setpriv --reuid=997 --regid=983 --clear-groups python3 - <<'PY'
import os
for path in ('/mnt/four-security/downloads/media', '/mnt/four-security/downloads/torrents/complete'):
    if not os.access(path, os.R_OK | os.X_OK):
        raise SystemExit('Scanner cannot read/traverse: ' + path)
PY
  fi
  if (( dry_run )); then
    log 'Mount dry-run complete; live mount/access verification was not performed.'
  else
    log 'Mount verified. Next: sudo bash scripts/install-suite.sh --dry-run'
  fi
  exit 0
fi

log 'Check service identity and existing configuration before changing anything'
account=$(getent passwd 997 || true)
group=$(getent group 983 || true)
if [[ -n $account ]]; then
  IFS=: read -r account_name _ _ account_gid _ <<< "$account"
  [[ $account_gid == 983 && ( $account_name == scanner || $account_name == four-security ) ]] || die 'UID 997 is used by an incompatible account. No account will be reassigned.'
else
  ! getent passwd scanner >/dev/null || die 'Name scanner already exists with another UID.'
fi
if [[ -n $group ]]; then
  group_name=${group%%:*}
  [[ $group_name == scanner || $group_name == four-security ]] || die 'GID 983 belongs to an unrelated group.'
else
  ! getent group scanner >/dev/null || die 'Group scanner already exists with another GID.'
fi
for path in /etc/four-security /var/lib/four-security /var/lib/clamav "$mount_path" "$credentials" /etc/four-security/scanner.json; do
  [[ ! -L $path ]] || die "Refusing a symlink at $path"
done
if ! awk -v target="$mount_path" -v source="$nas_source" '
  /^[[:space:]]*#/ || NF == 0 { next }
  $2 == target { count++; if ($1 != source || $3 != "cifs" || ("," $4 ",") !~ /,ro,/ || ("," $4 ",") ~ /,rw,/) bad=1 }
  END { exit (count > 1 || bad) }
' /etc/fstab; then
  die 'Existing fstab entry is duplicated or differs from the expected read-only NAS share. Review /etc/fstab.'
fi

units=(four-security-scan.timer four-security-discover.timer four-security-report.timer
       four-security-scan.service four-security-discover.service four-security-report.service clamav-freshclam.service)
native_present=0
for unit in "${units[@]}"; do
  if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    echo "  Native job enabled/active: $unit"
    native_present=1
  fi
done
(( ! native_present || migrate )) || die 'Rerun with --migrate-native to stop native jobs and snapshot their data first.'
if command -v docker >/dev/null; then
  # Do not change state/permissions underneath a running suite.
  running=$(docker ps --filter label=com.docker.compose.project=four-security --format '{{.Names}}') || die 'Docker is installed but its daemon is unavailable; start it and rerun.'
  [[ -z $running ]] || die 'Suite containers are running. Stop the suite before host preparation.'
  docker compose version >/dev/null || die 'Existing Docker lacks Compose v2. Install its matching Compose plugin, then rerun.'
  have_docker=1
else
  have_docker=0
  for package in docker.io docker-compose docker-doc docker-buildx podman-docker containerd runc; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]]; then
      die "Conflicting package $package is installed. Review its workloads and remove the conflict manually."
    fi
  done
  if grep -Rqs 'download.docker.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
    die 'A Docker apt repository already exists but Docker is incomplete. Finish/review that installation first; no duplicate repository will be added.'
  fi
fi

log 'Snapshot the existing native configuration and state before migration'
needs_snapshot=$migrate
for path in /etc/four-security /var/lib/four-security /var/lib/clamav; do
  if [[ -e $path ]]; then needs_snapshot=1; fi
done
if (( needs_snapshot )); then
  native_backup="/var/backups/four-security-native-$(date +%Y%m%d-%H%M%S)-$$"
  run install -d -o root -g root -m 0700 "$native_backup"
  if (( ! dry_run )); then
    for unit in "${units[@]}"; do
      printf '\n%s\n' "$unit"
      systemctl is-enabled "$unit" || true
      systemctl is-active "$unit" || true
    done > "$native_backup/unit-state.txt"
  fi
  if (( migrate )); then
    for unit in "${units[@]}"; do
      if systemctl cat "$unit" >/dev/null 2>&1; then
        run systemctl disable --now "$unit"
      fi
    done
  fi
  # Include manually started engines/updaters; do not take a live SQLite snapshot.
  if pgrep -af '(^|/)(freshclam|clamscan|yara)( |$)|[f]our_securitycenter.py' ; then
    if (( ! dry_run )); then die 'Scanner/updater processes remain. Stop their owning jobs and rerun.'; fi
    echo '  Dry-run: remaining processes must be gone before the actual snapshot.'
  fi
  for path in /etc/four-security /var/lib/four-security /var/lib/clamav /etc/fstab; do
    if [[ -e $path ]]; then run cp -a --parents "$path" "$native_backup/"; fi
  done
  log "Native snapshot (includes credentials; keep root-only): $native_backup"
fi

log 'Install host tools (scanning engines are installed in the image)'
run apt-get update
run apt-get install -y --no-install-recommends --no-upgrade ca-certificates curl gnupg python3 util-linux cifs-utils
if (( ! have_docker )); then
  log 'Configure the official Docker Debian repository and install Engine + Compose'
  run install -d -m 0755 /etc/apt/keyrings
  run curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  run chmod a+r /etc/apt/keyrings/docker.asc
  run gpg --show-keys --with-fingerprint /etc/apt/keyrings/docker.asc
  echo '  + write /etc/apt/sources.list.d/docker.sources (Debian trixie / arm64)'
  if (( ! dry_run )); then
    cat > /etc/apt/sources.list.d/docker.sources <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: arm64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  fi
  run apt-get update
  run apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  log 'Reuse the existing Docker Engine and Compose; no Docker upgrade'
fi
run systemctl enable --now docker
run docker version
run docker compose version

log 'Create/reuse the scanner service identity: UID 997, primary GID 983'
if [[ -z $group ]]; then run groupadd --system --gid 983 scanner; fi
if [[ -z $account ]]; then run useradd --system --uid 997 --gid 983 --no-create-home --shell /usr/sbin/nologin scanner; fi
log 'Prepare local configuration and writable state; never chown the NAS'
run install -d -o root -g 983 -m 0750 /etc/four-security
for path in /var/lib/four-security /var/lib/clamav; do
  run install -d -m 0750 "$path"
  run chown -R --no-dereference 997:983 "$path"
  run chmod -R u+rwX "$path"
done
if [[ ! -e /etc/four-security/scanner.json ]]; then
  run install -o root -g 983 -m 0640 config/scanner.json /etc/four-security/scanner.json
else
  log 'Keep existing scanner.json; grant the service group read access'
  run chown root:983 /etc/four-security/scanner.json
  run chmod 0640 /etc/four-security/scanner.json
fi
if [[ ! -e $credentials ]]; then
  echo "  + create root-only credential template: $credentials (password is never echoed)"
  if (( ! dry_run )); then
    install -o root -g root -m 0600 /dev/null "$credentials"
    printf 'username=CHANGE_ME\npassword=CHANGE_ME\n' > "$credentials"
  fi
else
  log 'Keep existing SMB credential contents; enforce root-only permissions'
  run chown root:root "$credentials"
  run chmod 0600 "$credentials"
fi
if ! findmnt -rn -M "$mount_path" >/dev/null; then
  if [[ ! -d $mount_path ]]; then run install -d -m 0755 "$mount_path"; fi
else
  log 'Existing mount point left untouched (no chmod/chown on the NAS)'
fi
if ! awk -v target="$mount_path" '$1 !~ /^#/ && $2 == target { found=1 } END { exit !found }' /etc/fstab; then
  echo '  + append one read-only CIFS entry to /etc/fstab (original saved as fstab.four-security.TIMESTAMP.PID)'
  if (( ! dry_run )); then
    cp -a /etc/fstab "/etc/fstab.four-security.$(date +%Y%m%d-%H%M%S).$$"
    printf '\n%s %s cifs credentials=%s,ro,vers=3.0,uid=997,gid=983,file_mode=0440,dir_mode=0550,nosuid,nodev,noexec,_netdev,nofail,x-systemd.automount 0 0\n' "$nas_source" "$mount_path" "$credentials" >> /etc/fstab
  fi
else
  log 'Reuse the existing fstab entry; --mount will validate the live mount and scanner access'
fi
run systemctl daemon-reload
if (( dry_run )); then
  log 'Dry-run complete. No changes made; package downloads and provisioning have not been tested.'
else
  log 'Host preparation complete. Containers and automatic scans have not been started.'
fi
echo "Next: sudoedit $credentials (only if the NAS account is not already configured)"
echo 'Then: sudo bash scripts/pre-req.sh --mount'
echo 'Then: sudo bash scripts/install-suite.sh --dry-run && sudo bash scripts/install-suite.sh'
echo 'Then: sudo ./suite start && sudo ./suite doctor'
