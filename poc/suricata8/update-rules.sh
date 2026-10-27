#!/bin/bash
set -euo pipefail
cd /opt/four-security/poc/suricata8
exec 9>/run/lock/four-ids-poc-update.lock
flock -n 9 || exit 0
# Root-owned file containing only a validated image digest.
source .env
stage=$(mktemp -d /var/lib/four-security/ids-poc/update-XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/rules" "$stage/cache"
if [[ -d /var/lib/four-security/ids-poc/cache ]]; then
  cp -a /var/lib/four-security/ids-poc/cache/. "$stage/cache/"
fi
docker run --rm --memory 512m --cpus 0.5 --pids-limit 64 --cap-drop ALL \
  --security-opt no-new-privileges:true --user 0:0 --read-only \
  --tmpfs /tmp:size=64m --entrypoint suricata-update \
  -v /etc/four-security/ids-poc:/etc/suricata:ro -v "$stage:/data" \
  "$IDS_IMAGE" --data-dir /data --output /data/rules \
  --suricata-conf /etc/suricata/suricata.yaml --no-test --no-reload --fail
test -s "$stage/rules/suricata.rules"
docker run --rm --network none --memory 768m --cpus 0.75 --pids-limit 64 \
  --cap-drop ALL --security-opt no-new-privileges:true --user 0:0 --read-only \
  --tmpfs /tmp:size=64m --tmpfs /var/log/suricata:size=32m \
  --entrypoint suricata -v /etc/four-security/ids-poc:/etc/suricata:ro \
  -v "$stage/cache:/var/lib/suricata/cache" \
  -v "$stage/rules:/var/lib/suricata/rules:ro" "$IDS_IMAGE" \
  -T --init-errors-fatal -c /etc/suricata/suricata.yaml
live=/var/lib/four-security/ids-poc/rules/suricata.rules
mkdir -p /var/lib/four-security/ids-poc/cache
cp -a "$stage/cache/." /var/lib/four-security/ids-poc/cache/
if [[ -f "$live" ]]; then cp -p "$live" "$live.previous"; fi
chmod 0644 "$stage/rules/suricata.rules"
mv "$stage/rules/suricata.rules" "$live"
# A restart avoids holding old and new full rule engines in memory together.
start_sensor() {
  docker compose up -d --force-recreate sensor || return 1
  bash wait-ready.sh
}
if systemctl is-active --quiet four-ids-poc.service; then
  if ! start_sensor; then
    if [[ -f "$live.previous" ]]; then cp -p "$live.previous" "$live"; fi
    start_sensor
    exit 1
  fi
fi
date -u +%FT%TZ > /var/lib/four-security/ids-poc/rules/last-success.txt
