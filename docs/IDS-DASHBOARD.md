# Suricata dashboard alerts — October 26, 2026

Live dashboard: http://192.168.4.46:8099/ under **Network alerts · Suricata**.

When a rule matches, Suricata writes an EVE alert. A root-owned collector reads
the local logs incrementally and saves sanitized summaries. The existing restricted
NAS publisher includes that snapshot in status.json. The browser polls every 30
seconds and highlights **detections · review required**, with severity, timestamp,
signature ID, source/destination and protocol. Normal end-to-end delay is roughly
one to two minutes across collection, publication and browser refresh.

Delivery is dashboard-only, as requested. With the page closed, alerts are retained
for later review but no message is sent. No email, phone push, browser permission,
sound, network blocking, quarantine or file modification is added. Alert priority
comes from the rule; it does not prove an intrusion. No alerts does not prove safety.

## Display and retention

- Separate sensor health, 24-hour review counts, packet/drop/error counters and
  latest detections. Visible sensor/report warnings include stopped, unavailable,
  stale statistics, overdue publication, collector backlog and capture loss.
- Seven days or 20,000 alerts retained, whichever is smaller. Latest 50 published,
  initially ten displayed with Show more. Counts flag incomplete history if capped.
- Local marker SID 1000001 is labeled as a test and counted separately. ET diagnostic
  SID 2100498 remains reviewable because the signature could also match real traffic;
  the UI notes its use in setup diagnostics. Existing ET test entries are expected.
- Historical SID 2200121 messages are still visible, labeled historical decoder
  notices, and excluded from review counts because this exact rule was deliberately
  disabled after inspecting repeated unsupported Ethernet broadcasts. No broad
  category of threat rules is suppressed by the dashboard.
- Collector deduplication follows inode/offset cursors and stable alert IDs, including
  renamed/compressed logs and partial writes. Malformed records and backlog warn
  rather than claiming complete counts. The database is separate from scanner state.

Coverage remains the Pi's eth0 traffic with NAS 192.168.4.46 TCP/445 excluded. There
is no verified switch mirror/TAP or whole-home view. See [POC results](../poc/suricata8/RESULTS.md).

## Installed components

- /opt/four-security/src/ids_dashboard.py
- four-ids-dashboard.service and timer: run 30 seconds after completion, enabled at boot.
- /var/lib/four-security/ids-dashboard: root:GID983 mode 0750. SQLite/cursors stay
  private; report.json is root:GID983 mode 0640 for the existing UID997 publisher.
- /etc/four-security/publisher.json adds
  `"ids_report": "/var/lib/four-security/ids-dashboard/report.json"`.
- src/publish_reports.py treats missing/invalid IDS data as unavailable without
  stopping valid file-scan report publication. Original alert logs remain root-only.
- Website source is versioned in dashboard/site; deploy its assets to the existing
  four-media/media-hub/site Web Station root. Do not copy runtime reports into Git.

Only whitelisted alert summaries and capture counters are published. Packet payloads,
DNS history, HTTP URLs, credentials and Docker configuration are not published by
this integration. The existing dashboard has no login; anyone who can reach it can
read the published IP addresses and signatures. Its existing access boundary remains.

## Operation

```bash
sudo systemctl status four-ids-dashboard.timer --no-pager
sudo journalctl -u four-ids-dashboard.service -n 20 --no-pager
sudo systemctl start four-ids-dashboard.service
sudo systemctl start four-security-publish.service
```

Disabling only dashboard collection:

```bash
sudo systemctl disable --now four-ids-dashboard.timer
```

The old snapshot remains and the page flags it overdue after two minutes. This does
not stop Suricata. Stop its capture separately with `sudo systemctl stop four-ids-poc`.
To remove the integration, remove ids_report from publisher.json and the IDS page
section, then publish again. Do not delete the scanner database.

## Live acceptance

Collector unit tests cover rotation/compression deduplication, partial appends,
retention, malformed records, stale/stopped/restarted sensor state, explicit backlog,
noise history separation and failure isolation from scan publication. JavaScript
tests cover validation, review/loss states and stale/failed reports. Existing scan
reporting tests also passed (the Pi lacks the sibling-site/Node cross-project fixture).

A new harmless local ICMP marker reached the live dashboard as an additional local
test entry, alongside fresh sensor counters, after the services ran. Normal timers
were observed updating snapshots and publication afterward. The live site showed
Running, zero capture drops, the expected setup diagnostics/checksum warnings, and
the prior generic decoder history separately. No sensor/container restart was needed
for dashboard deployment. Sensor and scanner containers remained healthy/running.
