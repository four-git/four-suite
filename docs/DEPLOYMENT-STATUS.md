# Deployment verified — October 21, 2026

Completed NAS hosting, Pi migration/rebuild, publisher deployment, acceptance tests, reboot verification, schedule restoration, and reviewed legacy-unit archiving. Times below are America/New_York.

## Live environment

- Site: http://192.168.4.46:8099/.
- DSM: https://192.168.4.46:5001/.
- Document root: /volume1/local-share/four-media/media-hub/site.
- Web Station: 4.3.1-0530, static `four-media` service, Nginx, LAN HTTP portal 8099.
- Pi: four@192.168.4.51; hostname four-security; Debian 13 ARM64; Docker Compose v5.6.0.
- Running image: sha256:b884495876aa1cd276272d6131ac1675ad1f5ef6f3b9ca07b53f7d9ba7ef9266.
- Base: debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f.
- ClamAV 1.4.3, daily database 28160; YARA 4.5.2. Debian's packaged engine is retained; FreshClam logs an upstream newer-engine notice.
- Scanner schedule restored to 21600 seconds (6 hours), discovery to 3600 seconds (1 hour), exactly as before migration. Lifecycle boot startup enabled as before. New publisher timer enabled, 30 seconds after completion. IDS remains disabled.
- Publisher account: four-security, default users group only, SID S-1-5-21-408022000-432311312-4020195513-3056. Existing four-securitycenter-scan media account unchanged.
- Media source: //192.168.4.46/data, read-only at /mnt/four-security/downloads.
- Report source: //192.168.4.46/local-share/four-media/media-hub/site/data/security, read/write at /mnt/four-security/reports.
- Report credentials: /etc/four-security/report-smb.credentials, root:root 0600; publisher config root:GID983 0640. No credential values are recorded here or in source archives.

## Preservation and permissions

Before mutations, inspected hostname/platform, unit enablement/activity, Docker projects/health, mounts, free space, UID997/GID983, existing runtime directories, and original schedules. Dry-run passed before apply.

Migration retained 312 file records and all 12,983 original events. Every original event's ID, timestamp, kind, and raw evidence was compared after acceptance and preserved; structured mount prefixes were renamed. All original file fields/fingerprints were compared immediately after migration and matched except the mount prefix. Original schema had no runs table, so historic events were retained without fabricating completed-run metrics. Production rule bytes are unchanged, SHA256 ecc20bebe63f3ea21189e52e35cc110da3270a658aa5ba0a4091f3aca0322091.

Publisher has non-inheriting read/traverse access to the local-share root (required for CIFS share connection), traversal only through four-media/media-hub/site/data, and inheriting Modify access inside data/security only. Existing ACL entries were retained. Actual CIFS tests verified create/write/rename/delete in reports, denied writes to the share root, four-media, site, and sibling security project, denied reading security source, and denied mounting the media share with publisher credentials. Newly created report files were readable through Web Station. Temporary test files/mounts were removed.

Scanner network mode is none, root filesystem read-only, and media/rules/config/signature bindings read-only. Only scanner state is writable. No Pi HTTP port was introduced.

## Acceptance evidence

- Linux release tests: 51 tests, 50 passed, one skipped because sibling site and Node are absent on Pi. The actual published JSON separately passed the sibling site's real validator on Windows.
- systemd-analyze verify and Docker Compose config passed.
- First targeted scan of a previously CLEAN media file: run 1, CLEAN, one engine attempt per engine, 191.216937573 seconds.
- Repeat of same file: run 2, zero scan/engine attempts, one cached result, 0.257098231 seconds.
- Second previously CLEAN media file: run 3, CLEAN, one attempt per engine, 195.789686547 seconds.
- Browser showed active run 3 while retaining completed run 2 metrics. Run IDs, completion timestamps, durations, attempts, cache counts, file counts and genuine scan history match SQLite and published JSON.
- Final retained scan history: three real scans; file inventory CLEAN=11, PENDING=299, SKIPPED_SIZE_LIMIT=2. Current findings are two coverage warnings, not malware detections. Event count became 12,985 through the two new engine scans. These bounded checks do not establish full-library cleanliness.
- Stopped publisher timer and service for over two minutes; page displayed Report outdated / publication overdue. Restart restored fresh live reporting.
- One-shot publication with a deliberately mismatched SMB source failed closed. Previous JSON hash/content remained unchanged and valid; scanner container stayed healthy. Original config restored and successful publication verified.
- All application shortcut endpoints returned HTTP 200. Jellyfin playback was observed with a playing video, readyState=4 and advancing position, then stopped.
- Live headless browser checks at 1280 and 390 pixels: six shortcuts, no horizontal overflow, no JavaScript errors; screenshots visually inspected. In-app viewport emulation did not apply, so the existing headless Edge test runtime was used for those responsive checks.
- Scanner during engine scan: about 987 MiB RAM, one CPU core, no OOM kills; Pi retained over 2 GiB available memory. Updater database validation peaked at 871,878,656 bytes after the correction below. Disk remained about 12 GiB free.
- Reboot verified: boot ID changed from d2805c4f-be96-4dfd-9485-c601f44e79ac to 100d055b-e54d-4cc9-b9e4-833dc6108c7d. Reconnected by IP; hostname, mounts, original schedules, enabled lifecycle/timer, both healthy containers, and fresh publication verified after boot settled.
- Reviewed cleanup-preview output and archived seven unchanged legacy unit files and the recognized old CLI symlink into the private migration snapshot. Original source/data/config and old image retained. Routine CLI is /opt/four-security/suite.

## Deployment corrections retained in NAS source and Pi release

1. Converted config/freshclam.conf from CRLF to LF. FreshClam rejected the CRLF boolean configuration. Rebuilt the ARM64 image and verified successful parsing/startup.
2. Increased the signature updater's Compose memory limit from 256 MiB to 1 GiB after its database-test child was OOM-killed at the old limit. Actual database update/validation then passed, with no OOM events at the corrected limit. Scanner settings, media credentials, production rules and scan cadence were preserved.

NAS source and staged Pi copies of the corrected config and Compose file have matching SHA256 hashes. Runtime image/package and acceptance metadata are recorded in /opt/four-security/deployment-manifest.json.

## Recovery

Private snapshot on Pi:
/var/backups/four-security-migration/20261021-204236-1792629756914795178

Rollback command (also saved here outside the Pi):

```bash
sudo python3 /opt/four-security/scripts/migrate-to-four-security.py --rollback /var/backups/four-security-migration/20261021-204236-1792629756914795178
```

The snapshot contains credentials and remains root-only. Retained legacy paths: /opt/four-securitycenter, /etc/four-securitycenter, /var/lib/four-securitycenter. Retained legacy image: c1d304863bbd. Do not delete these until deliberately retiring rollback. New scan history would be archived by rollback, not merged into the old database.

Workstation ACL snapshot: C:\Users\danie\AppData\Local\Temp\four-security-nas-acls-before.json. It was taken after the initial local-share traversal grant and before descendant grants; subsequent share-root read metadata access was additive. Remove only publisher-specific grants if reversing NAS access, preserving other ACL entries.

Deployment screenshots: C:\Users\danie\.codex\visualizations\2026\10\22\01a160f7-fe72-7b13-8fbc-8ec0a16aa4b7\live-site-1280.png and live-site-390.png.
## Test-fixture correction

A post-deployment test rerun exposed an unmocked publisher stop in the backup fixture. The test stopped the timer; it was immediately re-enabled and fresh publication verified. The fixture now mocks stop_publisher, and its Linux tests were rerun while asserting the live timer remains active. Production scanner/history were unaffected.


## October 22 repair and post-reboot update

The current image is sha256:3914346b890ace60a1a0ae6676bf7219d26e0bc702afe641163a11e497b63676, with persistent ClamAV and YARA-X 1.22.0. See [scanner repairs](SCAN-FIXES-2026-10-22.md) and [NAS memory/reboot verification](POST-REBOOT-VERIFICATION-2026-10-22.md) for current settings, acceptance evidence, backups, and recovery. The October 21 values above are the original migration record.
