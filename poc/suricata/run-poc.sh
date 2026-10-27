#!/bin/bash
# Run on the Pi: sudo bash poc/suricata/run-poc.sh eth0
set -euo pipefail
cd /opt/four-security
interface=${1:?Specify the verified capture interface}
[[ "$interface" =~ ^[a-zA-Z0-9_.:-]+$ && -d "/sys/class/net/$interface" ]] || exit 2
docker compose config --quiet
image=$(docker compose images -q scanner | head -n 1)
[[ -n "$image" ]] || { echo 'Existing scanner image not found'; exit 2; }
config=$(realpath poc/suricata)
logs=$(mktemp -d /var/log/four-security/suricata-poc-XXXXXXXX)
chmod 0700 "$logs"
common=(--rm --user 0:0 --read-only --cap-drop ALL --security-opt no-new-privileges:true
  --memory 512m --cpus 0.5 --pids-limit 64 --tmpfs /tmp:rw,size=64m,mode=1777
  --log-driver json-file --log-opt max-size=5m --log-opt max-file=2
  --mount "type=bind,src=$config,dst=/etc/suricata,readonly"
  --mount "type=bind,src=$logs,dst=/var/log/suricata"
  --entrypoint suricata)
docker run "${common[@]}" --network none "$image" -T --init-errors-fatal -c /etc/suricata/suricata.yaml
echo "Validated configuration. Logs: $logs"
echo 'Starting a ten-minute passive capture. In another terminal, run the marker test from README.md.'
# timeout returns 124 when the intended capture window ends; preserve other failures.
set +e
timeout --signal=TERM --kill-after=30s 600s docker run "${common[@]}" --name four-suricata-poc \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_NICE \
  "$image" --init-errors-fatal -c /etc/suricata/suricata.yaml -i "$interface"
result=$?
set -e
if [[ $result -eq 124 ]]; then
  docker stop -t 20 four-suricata-poc >/dev/null 2>&1 || true
  exit 0
fi
exit "$result"
