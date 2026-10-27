# Static JSON reporting

Follow [environment setup](ENVIRONMENT-SETUP.md), then [deployment](DEPLOYMENT.md). The NAS document root is `local-share/four-media/media-hub/site`; published JSON lives under its `data/security` directory. The publisher source is `//192.168.4.46/local-share/four-media/media-hub/site/data/security`; the NAS four-security project is the release source, not an HTTP document root. The earlier Pi API/NAS relay design is replaced: no reporting HTTP service, report API token, or NAS Node backend is required.

The host publisher reads SQLite with read-only access, closes its local transaction/short idle scanner lock, verifies the separate writable CIFS mount, then writes indented JSON to a unique temporary file beside `status.json` and replaces it by rename. Failed reads/writes retain the previous report. It does not initialize/repair the database or hold scanner locks during SMB operations. Scanner isolation and the read-only media mount remain unchanged.

`/etc/four-security/publisher.json` follows `config/publisher.json.example`: scanner config path, report mount, expected SMB source, fixed output `status.json`, and recent-run count (1–100; default 20). Incorrect/missing/wrong-source/read-only mounts fail; local fallback output is refused. Configure the actual source, not an assumed NAS volume.

## Version 1 format

Suricata dashboard integration is documented in [IDS-DASHBOARD.md](IDS-DASHBOARD.md).
When configured, `ids` is an optional additive field in this schema; file-scan fields
retain their existing meanings. IDS snapshot failure does not stop scan publication.

| Field | Meaning |
| --- | --- |
| `schema_version` | 1; unsupported versions rejected by page |
| `generated_at` | Unix seconds when local snapshot was read |
| `latest_scan`, `latest_completed_scan` | Latest real scan/completed real scan within retention; null if absent |
| `active_run` | Active scan/discovery/dry run, labelled accordingly; otherwise null |
| `file_counts` | Last recorded file statuses; not a fresh filesystem inventory |
| `recent_runs` | Latest real scans, default 20; excludes discovery/dry runs |
| `retained_scan_count`, `retention_days` | Real scans within history, default 30 days; not lifetime totals |
| `stale_scan_seconds` | Completed-scan freshness threshold, default 86400 |
| `findings` | All current malware/YARA/errors/partial/size-skip results, plus still-pending changed-file events |
| `coverage_note` | Explicit observation and coverage limitations |

Runs retain ID, action, scope, dry-run flag, timestamps, duration, state, failure reason and summary. Summary distinguishes visited files, actual scan attempts, per-engine attempts, cached results, per-status counts, discovery truncation, limits and engine versions. Both engines skipping a file is not a scan attempt. Cached detections are existing observations, not new detections. Repeated attempts across runs are not unique lifetime files.

States are running/completed/failed/interrupted. Detections alone do not fail execution. Completed means a bounded job finished, potentially with incomplete coverage. Hard-killed runs are projected interrupted when the scanner lock is free, using last progress time as end time. Scanner startup persists reconciliation; reporting never changes state.

Findings include scanner absolute `path`, derived SMB `share_path`, kind, observation time, evidence and an observation note. No NAS `/volume...` path is guessed. Raw historic engine output retains old paths/names where applicable. YARA is a review indicator, not confirmed malware. File existence has not been rechecked.

The timer waits 30 seconds after each run; the browser independently polls every 30 seconds with cache bypass/five-second request timeout. Allow roughly a minute plus publication time for visible changes. Publication older than two minutes is flagged separately from scan staleness. Fetch failures retain the browser's last successful payload and original timestamp; reload clears that browser memory, while the NAS report remains until replaced. Missing/uninitialized/corrupt databases do not produce a fresh-looking empty report. Valid empty history explicitly means never scanned.

The section below the six icons shows completed metrics, active progress, issue/coverage counts and recent scans. Findings use text rendering, show 20 at a time and offer access to all remaining rows. No whole-library-clean claim follows a bounded run. Only the publisher account writes the report folder; Web Station reads it. Anyone reaching the site can read published paths. Credentials/configuration dumps are excluded. No API endpoints, scan controls, notifications, quarantine or media writes are added.

The separate network-alert section adds visible dashboard status and detections.
There is still no external email, phone push, browser permission prompt, quarantine
or traffic blocking. Anyone reaching the site can also read the published alert
signatures and source/destination addresses.

Executable/script policy findings use POLICY_VIOLATION and appear among review findings and issue counts. They are separate from confirmed malware detections. Source files are never executed, moved or deleted by this policy. Large YARA-only results remain PARTIALLY_SCANNED; removing the application size cap does not imply complete antivirus coverage.
