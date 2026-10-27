# Local validation — October 21, 2026

Implemented locally: renamed runtime/source files, journaled Pi migration/rollback/cleanup preview, static JSON exporter/publisher and units, publisher lifecycle integration, NAS page metrics/findings/history, and the split environment/deployment guides. The old HTTP API/container/token design is removed. Existing uncommitted scanner work was retained.

## Passed

- Python unittest discovery: **42 reported entries, 39 passed and 3 skipped** on Windows. Coverage includes reports/retention/counters, 125+ findings without truncation, metadata and in-scan file changes, atomic write failures, mount/source validation, publisher lifecycle, and generated JSON consumed by the actual sibling site's validator.
- Migration fixtures: apply/rollback, partial failure at mount activation, destination conflicts, database path collisions with transaction rollback, old schemas, run scopes/interruption, cache/evidence preservation, logrotate migration, cleanup preview and restoration of archived unit definitions. Host commands, Linux UID enforcement and Windows-unavailable flock primitives are stubbed in these fixtures; they do not prove real systemd/CIFS behavior.
- Five Node logic tests: invalid schema/values, never-scanned state, timestamps/outages, issue/coverage distinctions and durations.
- Headless Edge/Playwright browser checks at 1280px and 390px: six shortcuts, actual rendered metrics, long Unicode/HTML-looking paths displayed as text, 20-row pagination with all findings accessible, unavailable/malformed/outdated reports, polling recovery, active scans and never-scanned state. No page JavaScript exceptions or mobile horizontal overflow. Screenshots in `four-media/media-hub/test-results/` use simulated data, not actual NAS results.
- Python compilation and Bash syntax checks for all shipped shell scripts. `git diff --check` passed.

## Still requires the Pi/NAS

No Linux runtime, Docker daemon or systemd was available on this workstation. The three skip entries cover the Linux scanner engine/file-descriptor test module, Linux-root host-preparation dry-run harness, and numeric ownership backup/restore test. Run the full suite with sudo on the Pi before migration, as documented.

The ARM64 rebuild, actual migration/rollback, systemd unit verification, SMB subdirectory/source display and ACLs, Web Station document root/portal, real scan comparison, NAS outage/recovery, resource observation during playback, and reboot acceptance remain live deployment checks. No Pi/NAS service or website was changed from this workstation.

## Local folder and test cleanup notes

Windows refused to rename the open checkout directory because another process is using it. Its top-level folder is still `four-securitycenter`; source filenames and runtime identities are renamed. [Deployment](DEPLOYMENT.md) includes the one-time folder rename after closing the workspace and packaging that works from either local name. The remote GitHub URL is unchanged.

An early Windows-only test-path issue created two disposable simulated backups outside the fixture directory. It was fixed and subsequent fixture runs stayed inside their temporary directories and cleaned up normally. Automatic approval review rejected removal of the two earlier folders with only “blocked by policy” as its reason. They remain available for manual inspection/removal:

- `C:\var\backups\four-security-migration\20261021-172812-1792618092867525500`
- `C:\var\backups\four-security-migration\20261021-172813-1792618093249066600`

These contain synthetic test files, not real NAS/Pi state or credentials. No cleanup of those two folders was forced after the rejection.

## Subsequent live deployment — October 21, 2026

The pre-deployment limitations above are historical. ARM64 migration/rebuild, publisher permissions, real scan/cache and report comparisons, layout/playback, outage/failure recovery, and reboot verification have now passed. See [deployment evidence and recovery](DEPLOYMENT-STATUS.md) for exact results and the two deployment corrections.
