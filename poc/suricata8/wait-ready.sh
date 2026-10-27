#!/bin/bash
set -euo pipefail
for attempt in {1..300}; do
  [[ $(docker inspect -f '{{.State.Running}}' four-ids-poc) == true ]] || exit 1
  started=$(docker inspect -f '{{.State.StartedAt}}' four-ids-poc)
  if docker logs --since "$started" four-ids-poc 2>&1 | grep -q 'Engine started'; then exit 0; fi
  sleep 2
done
echo 'Suricata did not report engine readiness within ten minutes' >&2
exit 1
