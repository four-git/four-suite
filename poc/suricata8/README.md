# Suricata 8 passive IDS POC

This is the ongoing Pi sensor, separate from the bounded Suricata 7 plumbing test
in ../suricata. See RESULTS.md for live acceptance and limitations.

The sensor listens on eth0 and alerts; it does not block. It explicitly excludes
TCP/445 traffic to/from NAS 192.168.4.46 using capture.bpf. The unfiltered full-rule
run dropped heavily during an SMB burst, so this Pi POC does NOT inspect those
file transfers or provide reliable unfiltered gigabit coverage.
HOME_NET is the verified
192.168.4.0/22 subnet plus the Pi's observed ULA/global IPv6 /64 networks and link-local
IPv6. Recheck HOME_NET if the ISP changes the global IPv6 prefix.
Other devices' unicast traffic requires a switch mirror/TAP
or gateway placement; no whole-LAN visibility is claimed. TLS payloads are encrypted.
The local marker rule is a diagnostic, not an intrusion. ET Open provides the threat
signatures, downloaded by the official suricata-update tool.

## Controls on the Pi

```bash
sudo systemctl status four-ids-poc --no-pager
sudo python3 /opt/four-security/poc/suricata8/status.py
sudo docker logs --tail 50 four-ids-poc
sudo tail -n 20 /var/log/four-security/ids-poc/fast.log
sudo systemctl stop four-ids-poc
sudo systemctl start four-ids-poc
```

`active (exited)` describes the successful Compose launch; check the container,
recent packet counters and logs as well. Zero alerts does not prove traffic is safe.
An alert needs investigation and can be a false positive.

Rules update daily at 4:30–5:00 AM America/New_York and after a missed run. New rules
are staged, validated with the installed engine, then atomically installed. A sensor
restart applies them and briefly interrupts capture. The previous rules are retained.
Engine images are pinned by digest and require a deliberate upgrade; the rule timer
does not update the engine. The container image is maintained by jasonish, not OISF.

```bash
sudo systemctl start four-ids-poc-update.service
sudo journalctl -u four-ids-poc-update.service -n 60 --no-pager
sudo systemctl list-timers 'four-ids-poc-*'
```

The sensor is limited to 768 MiB and 1.0 CPU; rule downloading uses 512 MiB and
0.5 CPU. These are ceilings, not reservations. Full ET rule memory usage is measured
in RESULTS.md. The file scanner retains its existing limits and schedules.

Compiled pattern caches persist on the Pi, with a seven-day pruning age. Rule
validation gets a separate copy of the cache, avoiding concurrent cache writes
between validation and the running sensor. Changed signatures are recompiled.

Log size is checked every 15 minutes, rotating at 20 MiB or daily with three archives.
This is approximate retention, not a hard disk quota: growth between checks can exceed
20 MiB. Docker console logs are separately capped at three 5 MiB files. No packet
payload capture/file extraction is enabled. EVE still contains sensitive metadata;
the host log directory is root-only. IDS events are not yet shown on the NAS dashboard.

Disable this POC and its timers without affecting the scanner:

```bash
sudo systemctl disable --now four-ids-poc-update.timer four-ids-poc-logrotate.timer
sudo systemctl stop four-ids-poc-update.service
sudo systemctl disable --now four-ids-poc.service
```

Retained paths: /etc/four-security/ids-poc, /var/lib/four-security/ids-poc,
/var/log/four-security/ids-poc, and /opt/four-security/poc/suricata8.
The older suite's optional Suricata profile stays disabled; do not enable a second
sensor on the same interface. This independent POC is controlled by four-ids-poc,
not the scanner suite's start/stop command.

## Harmless detection checks

On the Pi, this emits the local diagnostic signature 1000001:

```bash
ping -c 3 -p 464f55522d5355524943415441 192.168.4.46
```

From Windows PowerShell, this emits a local UDP packet matching the ET diagnostic
signature 2100498. It opens no service, exploits nothing and executes no command
on the Pi. The returned ICMP error may also match because it quotes the packet.

```powershell
$idsUdp = New-Object System.Net.Sockets.UdpClient
$idsBytes = [Text.Encoding]::ASCII.GetBytes('FOUR IDS harmless test uid=0(root)')
$idsUdp.Send($idsBytes, $idsBytes.Length, '192.168.4.51', 49098)
$idsUdp.Dispose()
```

Do not treat the signature's "returned root" wording as a compromise in this test.
The testmynids.org endpoint in the upstream guide returned a parked-domain page
during this deployment, so it is not used for ongoing validation.

One decoder signature, 2200121 (unknown EtherType), is disabled in disable.conf
after verifying repeated broadcast EtherType 0x9104 frames on this LAN. This is
noise tuning, not identification of that protocol or proof its traffic is harmless.
Other decoder and ET threat signatures remain enabled. A few checksum warnings
were observed with NIC checksum offload enabled; they remain visible for review.
The status helper summarizes only the current log, not rotated history.

## Deployment record

The source files here were staged to /opt/four-security/poc/suricata8, root-owned.
The image was pulled by version and its immutable digest recorded in the Pi's .env.
The image entrypoint generated stock config/support files in /etc/four-security/ids-poc
using `-V`; configure.py then adjusted that configuration. Root ownership is required
after generation because the image initializes files under its own account.
The earlier local.rules was installed beside that config. update-rules.sh performed
the initial validated rule download before installing/enabling the provided systemd
units. The custom logrotate.conf is invoked by its own timer, not installed globally.

References:
- https://suricata.io/our-story/eol-policy/
- https://github.com/jasonish/docker-suricata
- https://docs.suricata.io/en/suricata-8.0.7/rule-management/suricata-update.html
