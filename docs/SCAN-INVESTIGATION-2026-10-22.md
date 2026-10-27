# Scan investigation — October 22, 2026

Read-only investigation of failed run 16 (09:32:27–09:47:27 America/New_York). Runtime and NAS scanner source hashes match: 43a80219c7c16f59af2b12b7fd8faed1e4259e6d4ac87940181240d080415d5a.

## Confirmed failure

Run reached its 900-second limit after visiting six files: three SCAN_ERROR, two SKIPPED_SIZE_LIMIT, one CLEAN. Four files received engine attempts. No malware detection was recorded in these run events.

- Two files under torrents/complete returned ClamAV Heuristics.Limits.Exceeded.MaxScanTime at the configured 240,000 ms per-file scan limit. Their YARA invocations returned exit 0.
- A media MP4 was interrupted after approximately 122 seconds when the remaining whole-run budget expired; YARA was not attempted for that file.
- Two oversized movie files were skipped by both configured engine size limits.

Both containers are healthy, the lifecycle service and publisher timer are active, signatures are current (daily 28161), and the scanner cgroup reports zero OOM kills. The failure was not a service crash or publisher outage.

## Confirmed bookkeeping defect

In src/four_security.py::_scan, unchanged records which are not cache-eligible enter the default PENDING path during discover_only runs. The final INSERT OR REPLACE stores last_attempt=None, versions='', and empty engine/evidence fields. This overwrites prior SCAN_ERROR state and loses its attempt timestamp in the current file inventory; historical events remain retained.

All three failed-run paths now show PENDING, last_attempt NULL, empty versions and reason {}. Their event chains explicitly show run 16 SCAN_ERROR followed by runs 17–21 PENDING. Across 369 file records, 366 have last_attempt NULL.

This undermines the oldest-attempt-first ordering: failed files become indistinguishable from never-attempted files and can repeatedly consume the limited budget. It also removes current-error visibility from the findings inventory after discovery.

Recommended correction: discovery should refresh metadata without replacing unchanged scan outcomes, engine evidence, fingerprints, or attempt timestamps. Changed-file pending state and last-attempt scheduling semantics should be handled explicitly. Add regression coverage for scan-error → discovery → next scan ordering and for signature changes before adjusting runtime/per-file limits. Consider a separate deferred/budget-exhausted outcome so the last file is not reported as an engine failure merely because the batch budget expired.

No runtime settings, service schedules, media files, scanner code, or database records were changed during this investigation. No additional scans were started.