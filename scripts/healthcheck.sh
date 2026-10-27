#!/usr/bin/env bash
# Read-only diagnostics only. Does not modify the Pi, NAS or any service.
set -u
printf '%s\n' '=== four-security: basic health (read-only) ==='
date --iso-8601=seconds
hostnamectl --static || true
cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID|VERSION_CODENAME)=' || true
dpkg --print-architecture || true
free -h || true
df -h / /var || true
systemctl --failed --no-pager || true
for service in clamav-freshclam suricata; do
  printf '\nService %s: ' "$service"
  systemctl is-active "$service" || true
done
printf '\nNAS SMB mount: '
findmnt -T /mnt/four-security/downloads -t cifs -o SOURCE,TARGET,FSTYPE,OPTIONS || echo 'NOT CONFIRMED (not necessarily configured yet)'
echo 'NOTE: Active services / mount presence alone do not prove malware or whole-LAN detection.'
