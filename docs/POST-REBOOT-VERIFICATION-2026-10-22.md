# Post-reboot verification — October 22, 2026

Verified after the NAS RAM upgrade and reboot, approximately 7:20–7:35 PM America/New_York.

## NAS

DSM Resource Monitor recognizes 10 GB of physical memory. At verification it used about 1.3 GB (13%), with roughly 5.2 GB free plus 3 GB cached. DSM reports system health Healthy. This confirms detection and normal operation after reboot; no additional reboot or memory stress test was performed.

Jellyfin, Radarr, Sonarr, Prowlarr, qBittorrent, FlareSolverr and the Web Station dashboard all returned HTTP 200. The first four media containers and Gluetun had returned after reboot. qBittorrent was stopped; starting the existing downloads project waited for Gluetun health and then started qBittorrent successfully. Its configuration still uses network_mode service:gluetun with service_healthy dependency. Its executable/script exclusions remain enabled with all fourteen saved patterns. Download/configuration folders were preserved.

Production FlareSolverr had been stopped since an earlier Chrome startup failure. Starting it with the upgraded NAS memory passed its browser self-test and served the ready API on port 8191 (FlareSolverr 3.5.2 / Chrome 152). Its automatic-restart flag had been disabled; it is now enabled and was verified by reopening container details. Only that container was stopped briefly to change its setting. The matching compose service restart policy is now always; the original file is backed up as /volume1/docker/four-media-service/compose.before-flare-autostart-20261022.yaml. Other compose settings and container IDs were retained. The existing diagnostic container remains stopped; it has a finite diagnostic/sleep command and no production role. A project-level Start temporarily started that diagnostic as well; it was returned to its original stopped state. Its presence can leave a partial-project warning even when all production services are running. The empty historical radarr project was retained; the actual Radarr container runs in four-media-service.

## Pi scanner

Both production containers are healthy, with zero restarts and no OOM flag. Media CIFS remains read-only/noexec; report CIFS is writable only through the existing report publisher account. Publishing resumed after NAS recovery, and current JSON reaches the dashboard.

Run 40 was interrupted by the NAS outage with Host is down; it and the failed discovery remain in history. The queue was resumed. Run 43 is an automatic scan of both torrents/complete and media. At verification the retained inventory was 65 CLEAN, 300 PENDING, two POLICY_VIOLATION and two historical SKIPPED_SIZE_LIMIT observations. These are latest recorded results, not a completed full-library safety verdict. The two policy findings are the Lanterns episode 5 .exe and the extensionless episode 6 download. They were not executed, moved or deleted.

The scanner now retries mount/preflight/runtime outages after five minutes. Ordinary per-file engine errors retain their separate six-hour backoff. The scheduling regression passed, as did the full Linux suite: 64 tests, 63 passed and one cross-project frontend skip. The six frontend tests passed separately. The ARM64 YARA-X adapter passed clean, embedded PE, script indicator and late PE beyond one million decoy matches. Earlier full-file YARA-X acceptance scanned 19,902,640,891 bytes in 872.675 seconds with no rule matches.

Final immutable image: sha256:3914346b890ace60a1a0ae6676bf7219d26e0bc702afe641163a11e497b63676. Engines: ClamAV 1.4.3 and YARA-X 1.22.0. YARA rules SHA256 remains ecc20bebe63f3ea21189e52e35cc110da3270a658aa5ba0a4091f3aca0322091. ClamAV retains its 1.9 GB configured ceiling; large-file YARA-only checks are partial coverage.

Stopped backup before the outage retry update: /var/backups/four-security/20261022-192924-1792711764424737982, with release-before-outage-retry.tar.gz. The original pre-repair backup and its complete prior release remain at /var/backups/four-security/20261022-144629-1792694789710777539. Use the suite rollback procedure with the matching source archive; rollback first saves the newer runtime state. Credentials remain on the Pi. No media or historical scan records were deleted.
