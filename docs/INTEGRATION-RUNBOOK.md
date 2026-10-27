# four-security integration: start here

The rename migration, JSON publisher, systemd units, website section, and local tests are implemented. The projects now live at `\\four-nas\local-share\four-media` and `\\four-nas\local-share\four-security`. Pi runtime migration, Web Station hosting, publishing and live acceptance were verified October 21, 2026. See [actual deployment values, evidence and rollback](DEPLOYMENT-STATUS.md). For future deployments, follow these guides in order:

1. **[Environment setup](ENVIRONMENT-SETUP.md):** prepare Web Station, NAS folders/permissions, SSH access, and record deployment values. This does not rename or stop the Pi installation.
2. **[Deploy the scanner and website](DEPLOYMENT.md):** copy the completed release, migrate to `four-security`, rebuild/start the suite, point Web Station at the existing site folder, enable publishing, and verify the full path. Includes rollback and legacy-cleanup commands.

No application code needs to be written while following the guides. Supply your actual Pi login, NAS volume, portal URL, and DSM account. Enter passwords directly into root-only files on the Pi.

Use `local-share/four-media/media-hub/site` as the Web Station document root, with reports under `site/data/security`. Stage the scanner from the NAS four-security project into `/opt/four-security` on the Pi. The NAS project name is already correct; the Pi rename is still covered by Part 2. Keep runtime SQLite state and credentials on the Pi.

```text
Pi scanner -> local SQLite -> host publisher -> NAS report folder
                                                    |
Browser <- Web Station <- HTML/CSS/JS + status.json
```

The publisher waits 30 seconds after its previous execution; the page polls every 30 seconds. Allow roughly a minute plus processing/network time for a visible change. No Pi HTTP port is opened. The scanner remains isolated from networking and its media mount remains read-only.

See [validation](VALIDATION.md) for local results and host limitations, [reporting](REPORTING.md) for data semantics, and [Docker setup](DOCKER-RUNBOOK.md) for fresh installations and routine operation.

October 22 scanner repairs, large-file validation and recovery: [repair deployment](SCAN-FIXES-2026-10-22.md) and [post-reboot verification](POST-REBOOT-VERIFICATION-2026-10-22.md).
