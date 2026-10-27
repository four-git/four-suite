# four-security

A Raspberry Pi 4 / 4 GB security suite for read-only Synology NAS file scanning, with optional passive network IDS.

**Existing Pi installation and NAS dashboard:** follow [Part 1: environment setup](docs/ENVIRONMENT-SETUP.md), then [Part 2: deployment](docs/DEPLOYMENT.md). The rename migrator, JSON publisher, systemd units, and website section are implemented. Project roots are `\\four-nas\local-share\four-security` and `\\four-nas\local-share\four-media`; Web Station serves only `four-media/media-hub/site`. Pi/NAS deployment and live acceptance completed October 21, 2026. See [deployment evidence and recovery](docs/DEPLOYMENT-STATUS.md) and [local validation](docs/VALIDATION.md).

For a fresh host, use [Docker setup and operation](docs/DOCKER-RUNBOOK.md). Existing `four-securitycenter` deployments must use the rename migration guide above first.

Fresh-host setup scripts (not the existing-installation rename procedure):

```bash
# On the Pi, from /opt/four-security:
sudo bash scripts/pre-req.sh --dry-run --migrate-native
sudo bash scripts/pre-req.sh --migrate-native
# Enter NAS credentials with sudoedit if needed, then:
sudo bash scripts/pre-req.sh --mount
sudo bash scripts/install-suite.sh --dry-run
sudo bash scripts/install-suite.sh
sudo ./suite start
sudo ./suite doctor
```

For a fresh host, omit `--migrate-native`. Follow the guide's copy/staging step before these commands. Preparation prints progress, preserves existing config/data, and snapshots the native installation before migration. Automatic scans and Suricata remain disabled.

Target: `four-security` / `192.168.4.51`, Debian 13 ARM64. NAS: `four-nas` / `192.168.4.46`, share `//192.168.4.46/data`, mounted read-only at `/mnt/four-security/downloads`.

After validation, install **`four-security.service`** using the [systemd setup commands](docs/DOCKER-RUNBOOK.md#install-the-four-security-service). Then use `sudo systemctl start four-security`, `stop four-security` or `restart four-security` for lifecycle control. Automatic scan schedules are configured separately.

**Status:** The renamed ARM64 release passed migration, publishing, real scan/cache, permissions, playback/layout, outage/recovery, and reboot checks on October 21, 2026. Original 6-hour scan and 1-hour discovery schedules are restored; the publisher timer is enabled. See [deployment status](docs/DEPLOYMENT-STATUS.md). Prior native scanner results are recorded in the [Docker guide](docs/DOCKER-RUNBOOK.md#prior-native-validation).

ClamAV is configured up to 1.9 GB/file and uses a persistent local daemon. YARA-X 1.22.0 evaluates the two existing local rules over full files without an application size cap, within its size-scaled time budget; this remains narrow MKV/MP4 payload triage, not comprehensive antivirus coverage. Executables/scripts in media roots are flagged for review. See [repair deployment and limits](docs/SCAN-FIXES-2026-10-22.md) and [rule coverage](docs/RULE-COVERAGE.md). Suricata requires verified traffic capture before use.

The scanner never writes to the NAS. The optional separate publisher writes only to its dedicated report directory. No deletion, quarantine, blocking, public Pi web port or sample upload is added. Credentials stay on the Pi and out of Git/images.

## Read-only dashboard reporting

Suricata POC work and operating instructions are in [poc/suricata8](poc/suricata8/README.md).
The live [network-alert dashboard](docs/IDS-DASHBOARD.md) shows detections and sensor
health; notifications are dashboard-only. Website source is in [dashboard](dashboard/README.md).
It uses a separate supported Suricata 8 container and ET Open rules. See its live
acceptance record before interpreting coverage: the Pi's NAS SMB transfers are excluded,
and LAN-wide traffic visibility has not been established. The original suite IDS profile
remains disabled.

The host publisher exports run history, counts and findings with scanner/share paths as readable JSON. The static NAS page reads that file every 30 seconds without a login, API, or backend. See [report format and behavior](docs/REPORTING.md). Reporting is opt-in and does not enable scan schedules. Anyone reaching the page can read published paths.
