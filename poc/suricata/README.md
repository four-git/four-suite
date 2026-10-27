# Suricata POC — October 26, 2026

Status: deployed and live-tested on the Pi on October 26, 2026. See FINDINGS.md.

Suricata inspects network packets, identifies protocols, and matches detection rules.
This POC uses passive IDS capture and a harmless local rule. It does not block traffic.
It is a capture/detection plumbing test, not a malware coverage test. No community threat
rules are included yet. TLS payloads remain encrypted; protocol metadata may be visible.

## Live deployment gates

1. Restore SSH and sudo access. Inspect `ip -br address`, `ip route`, `free -h`,
   `df -h /var/log`, `docker stats --no-stream`, and existing scanner health.
2. Confirm the capture interface and actual LAN subnet. HOME_NET is provisionally
   192.168.4.0/22 (verified against the Pi route table).
3. Copy this directory into /opt/four-security/poc/suricata on the Pi. Set root:root
   ownership, directory mode 0755 and file modes 0644; the container drops DAC capabilities.
4. Run `sudo bash poc/suricata/run-poc.sh INTERFACE` from /opt/four-security.
   The script reuses the existing scanner image, validates rules/configuration first,
   and starts a separate container with a ten-minute time limit. Existing scanner
   containers and their schedules are not recreated. No boot service is added.

In another Pi SSH terminal, send a marker to the documented NAS address (verify first):

```bash
ping -c 3 -p 464f55522d5355524943415441 192.168.4.46
sudo docker stats --no-stream four-suricata-poc
```

The pattern is ASCII FOUR-SURICATA. Acceptance requires SID 1000001 in fast.log
and eve.json, increasing decoder packet counters, and checking capture drops,
engine errors, OOM status and scanner health. Preserve actual evidence before claiming
success. Stop early with `sudo docker stop four-suricata-poc`.
Logs remain in a unique root-only /var/log/four-security/suricata-poc-* directory.
The capture window and metadata-only event types limit growth; check disk space first.
Do not enable continuous operation without retention/log rotation and resource checks.

## Visibility and the next stage

A normal switched-network port does not receive other devices' unicast traffic.
Initially expect Pi traffic and some broadcast/multicast traffic. Promiscuous mode
alone does not provide whole-LAN visibility. Verify mirror/TAP traffic with a controlled
flow between two other devices before claiming network-wide coverage.

After this test succeeds, evaluate Emerging Threats Open rules with suricata-update
against the installed engine version, validate the resulting rules, measure memory
and packet drops during a real scan, and tune false positives. The suite's 512 MB
Suricata limit may be too small for a full ruleset alongside the scanner on a 4 GB Pi.
The existing NAS dashboard currently reports file scans; IDS events need separate
integration. A successful marker alert is expected test traffic, not an intrusion.

References:
- https://docs.suricata.io/en/suricata-8.0.2/quickstart.html
- https://docs.suricata.io/en/suricata-8.0.0/command-line-options.html
- https://docs.suricata.io/en/suricata-8.0.6/output/log-rotation.html
