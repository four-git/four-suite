# Suricata POC results — October 26, 2026

Suricata 8.0.7 is running on four-security / 192.168.4.51 as a separate passive
sensor. The original scanner and signature containers were not recreated and
remain healthy. The earlier Suricata 7 plumbing test stays stopped; 7.x is EOL.

## Installed behavior

- Service: four-ids-poc. Project directory: /opt/four-security/poc/suricata8.
- Engine: community jasonish/suricata 8.0.7 ARM64, pinned to
  sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26.
- ET Open plus bundled protocol rules: 53,272 enabled after tuning, plus one local
  diagnostic signature. Downloads and engine validation use suricata-update and -T.
- Capture: eth0, one AF_PACKET worker, tpacket-v3, ring size 8192, 768 MiB memory
  limit and one CPU ceiling. IPv4 /22 and observed local IPv6 networks are HOME_NET.
- The BPF filter excludes TCP/445 traffic to/from NAS 192.168.4.46. See below.
- Rules refresh daily at 4:30–5:00 AM America/New_York. Each candidate is validated
  before replacing live rules; a restart applies it, with a previous rules backup.
- Log sizes checked every 15 minutes; 20 MiB/daily rotation with three archives.
  Console logs separately capped. Retention is approximate, not a disk quota.
- A service readiness check waits for the engine, rather than just container launch.
  Sensor, rule-update timer and rotation timer are enabled for boot.

## Verification

1. Initial full rules passed engine validation. The managed systemd rule update also
   downloaded, staged, validated and applied rules, then waited for engine readiness.
   Its completed run is recorded in the system journal and last-success.txt.
2. Local ICMP marker: three packets generated three SID 1000001 alerts.
3. Controlled UDP text `uid=0(root)` from 192.168.4.85 to the Pi generated ET test
   SID 2100498, including a second match in the quoted ICMP error. No exploitation
   occurred. The public endpoint in the upstream quickstart returned a parked-domain
   page, so local controlled traffic was used instead.
4. Forced log rotation followed by a new marker proved logs reopen and keep recording.
5. With the final filtered configuration, a bounded 128 MiB direct read from the
   read-only NAS mount completed in 1.70 seconds (78.9 MB/s). The next capture sample
   showed 916 kernel packets, 916 decoded packets, zero kernel drops and zero capture
   errors. Only five deliberate test alerts appeared in the freshly rotated log.
   A follow-up sample reached 1,798 kernel packets with zero drops/errors; its
   timestamp was confirmed to be later than all detection tests.
6. At that sample the sensor used 446.1 MiB and 1.72% Docker CPU; OOMKilled=false,
   RestartCount=0. Both existing scanner containers remained healthy. The file scanner
   was active during testing (observed near its existing one-core CPU allocation).
7. Compose rendering, Bash syntax, Python compilation, systemd unit verification and
   logrotate configuration checks passed. The logrotate systemd service also ran.

Raw evidence remains on the Pi:

- /var/log/four-security/ids-poc/eve.json and fast.log, plus rotated archives.
- `journalctl -u four-ids-poc -u four-ids-poc-update -u four-ids-poc-logrotate`.
- /var/lib/four-security/ids-poc/rules/last-success.txt and suricata.rules.previous.
- /tmp/four-ids-poc-update.log for the initial validation (temporary).

EVE timestamps are UTC; the daily timer explicitly uses America/New_York.

## Important findings and limits

The unfiltered full-rule run was NOT reliable during a traffic burst: one sample
recorded 251,910 drops out of 445,839 kernel packets. This is why the final capture
filter excludes the Pi's high-volume NAS SMB path. A bounded transfer with that
filter produced zero drops in the measured sample. This does not demonstrate
unfiltered gigabit capacity, long-term stability or whole-LAN coverage. SMB transfers
on that path are outside IDS inspection; the existing file scanner remains separate.

Most first-run alerts were SID 2200121, "SURICATA Ethertype unknown". A short tcpdump
header inspection verified repeated LAN broadcasts with EtherType 0x9104. That single
decoder signature was disabled, leaving other decoder and threat rules enabled.
The protocol was not identified; suppressing this generic message is noise tuning,
not proof that the underlying traffic is benign. A few checksum decoder alerts were
also observed with NIC checksum offload enabled; those remain visible.

The user described an eero router and a simple Netgear switch without an interface.
No mirror/TAP was established. Expect the Pi's traffic and broadcast/multicast only.
An exact switch model is needed to assess port mirroring; no hardware purchase or
network topology change was made. TLS contents remain encrypted. Initial rule
compilation takes minutes on the Pi; cached startup still took about 74 seconds in
the final restart. Engine updates require a separate deliberate image upgrade.

There is no IDS dashboard or external notification integration yet. Read current
alerts using status.py or fast.log as described in README.md. No convincing malicious
activity was established from this short test; the observed test alerts are expected.
That is not evidence that the network is clean.

## Controls

```bash
sudo python3 /opt/four-security/poc/suricata8/status.py
sudo systemctl stop four-ids-poc
sudo systemctl start four-ids-poc
```

See [README.md](README.md) for rule updates, log locations, disabling the timers,
repeatable detection tests and coverage details.
