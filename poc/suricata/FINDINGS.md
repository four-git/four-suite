# Live POC findings — October 26, 2026

Installed at `/opt/four-security/poc/suricata` on `four-security` (192.168.4.51).
The existing suite image contains Suricata 7.0.10. This POC reuses that exact local
image rather than rebuilding the active scanner or downloading a new engine.

Verified network: wired eth0, 192.168.4.51/22, gateway 192.168.4.1. The Pi also
has Wi-Fi at 192.168.4.78; the test captures eth0 only. No mirror/TAP was verified.
Available memory before capture: 2.2 GiB. Disk space available: 10 GiB.

## Results

- Configuration and local rule passed the installed engine's `-T --init-errors-fatal`.
- Final capture started without warnings/errors, using one AF_PACKET worker and
  tpacket-v3. Earlier configuration experiments were corrected before this run.
- Three ICMP echo requests from the Pi to the NAS carried ASCII FOUR-SURICATA.
  All three generated local signature 1000001 alerts in fast.log and EVE JSON.
- Final capture counter: 1,127 kernel packets, zero kernel drops, zero capture
  errors. This is a short sample, not a throughput benchmark.
- Observed usage: 24.26 MiB of 512 MiB; 0.91% Docker CPU. OOMKilled=false.
- Existing scanner and signature containers stayed healthy; neither was recreated.
- Evidence directory on the Pi: `/var/log/four-security/suricata-poc-VX04Deoo`.
  Engine startup/validation output: `/tmp/four-suricata-poc-run.log`.
  Capture was stopped after verification. No boot service or automatic capture added.

## What this means

Packet acquisition, decoding, local rule matching and alert output work on this Pi.
The alert is deliberate test traffic, not evidence of an intrusion. This setup
currently has only that local rule: it is not yet a useful threat-detection ruleset.

The next experiment should add a measured selection of current ET Open rules using
suricata-update, validate compatibility with the installed engine, and measure memory
and drops while the file scanner is busy. The small local-rule footprint must not be
used to predict the footprint of tens of thousands of threat signatures.

For LAN monitoring, decide where traffic comes from: a managed switch mirror port,
network TAP, or gateway sensor. A spare Pi on a normal switch port cannot observe
arbitrary connections between other devices. We have only proven Pi-to-NAS traffic.
Encrypted sessions also limit payload inspection. Configure retention before any
continuous run; EVE metadata can contain addresses, DNS queries and HTTP URLs.

## Rerun

```bash
ssh four@192.168.4.51
cd /opt/four-security
sudo bash poc/suricata/run-poc.sh eth0
```

From another Pi session, after the engine reports Engine started:

```bash
ping -c 3 -p 464f55522d5355524943415441 192.168.4.46
```

The runner automatically stops after ten minutes. Stop sooner with
`sudo docker stop four-suricata-poc`. Logs persist in a unique root-only directory.

Official references: [quickstart](https://docs.suricata.io/en/suricata-8.0.2/quickstart.html),
[command options](https://docs.suricata.io/en/suricata-8.0.0/command-line-options.html),
[log rotation](https://docs.suricata.io/en/suricata-8.0.6/output/log-rotation.html).
Use the installed engine's validation as the compatibility check; documentation
links above describe newer stable versions.
