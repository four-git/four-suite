# Part 2 — Deploy the scanner, publisher, and Web Station site

Finish [environment setup](ENVIRONMENT-SETUP.md) first. All scripts/site changes below are included; no code-writing step remains. The project files are already stored on the NAS; the Pi runtime migration, Web Station portal and publishing service still require deployment/verification. Windows blocks use PowerShell; Pi blocks use Bash. Stop at failures rather than starting a partial migration.

## 1. Package and stage

Windows:

```powershell
$piLogin = 'YOUR_PI_USER@192.168.4.51'
$suiteRepo = '\\four-nas\local-share\four-security'
$suiteArchive = Join-Path $env:TEMP 'four-security-suite.tar.gz'
tar -czf $suiteArchive --exclude=__pycache__ -C $suiteRepo Dockerfile .dockerignore compose.yaml suite deployment-manifest.json README.md config docs rules scripts src systemd tests
if ($LASTEXITCODE -ne 0) { throw 'Archive failed' }
scp $suiteArchive "${piLogin}:/tmp/four-security-suite.tar.gz"
if ($LASTEXITCODE -ne 0) { throw 'Upload failed' }
ssh $piLogin
```

The archive excludes `.env`, `.git`, runtime databases/reports and passwords. Migration carries over Pi settings. Do not unpack over the old checkout or rely on `git pull` for unpublished desktop changes.

The NAS project is already named `four-security`; no Windows folder rename is needed for this deployment. The NAS holds the release source, while the running suite, state and credentials stay on local Pi storage.

Stage once on the Pi:

```bash
(
  set -e
  if sudo test -e /opt/four-security; then
    echo 'Destination exists: inspect previous staging/migration first.' >&2
    exit 1
  fi
  sudo install -d -m 0755 /opt/four-security
  sudo tar --no-same-owner -xzf /tmp/four-security-suite.tar.gz -C /opt/four-security
  sudo chown -R root:root /opt/four-security
  sudo chmod -R go-w /opt/four-security
  sudo python3 /opt/four-security/scripts/migrate-to-four-security.py --dry-run
)
```

Review inventory, old unit states, running services, paths, identities and free space. The dry run changes nothing. Run release tests on Linux before applying:

```bash
cd /opt/four-security
sudo python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Tests use temporary fixtures and stub migration host commands; they do not run a live migration. Resolve failures first.

## 2. Rename and rebuild the Pi suite

During the maintenance window:

```bash
sudo python3 /opt/four-security/scripts/migrate-to-four-security.py --apply
```

**Save its snapshot path and rollback command outside the Pi.** The root-only snapshot contains credentials. Migration journals before service changes, stops/disables legacy lifecycle/native jobs, shuts down the old Docker project without deleting volumes/images, and verifies no engines/updater remain. It snapshots stopped config/state/sidecars/signatures and preserves original stopped source/data for recovery.

It creates renamed config/state/log paths; transactionally rewrites structured database file/event paths and run scopes while retaining IDs/times/cache fingerprints; moves the read-only media mount; migrates an installed suite logrotate config; and changes the hostname to `four-security`. UID 997/GID 983 stay unchanged. Dedicated legacy-named accounts are renamed; generic `scanner` accounts stay as-is.

Active production rule bytes/custom rules are preserved so renaming alone does not invalidate caches. Their author metadata and raw historic evidence can retain legacy names; the harmless acceptance rule follows the new release. Original `.env` intervals are saved in the journal and temporarily set to zero. All jobs remain stopped. IDS and new schedules are not enabled. A partial migration must be recovered before continuing; repeated apply refuses to overwrite it.

Build/start the renamed release, one command at a time:

```bash
cd /opt/four-security
sudo bash scripts/install-suite.sh --dry-run
sudo bash scripts/install-suite.sh
sudo docker compose config --quiet
sudo install -m 0644 systemd/four-security.service /etc/systemd/system/four-security.service
sudo systemctl daemon-reload
sudo systemctl start four-security.service
sudo ./suite doctor
sudo ./suite status
sudo ./suite alerts
```

The old image embeds old paths, so rebuilding is required. Keep old images for recovery. `active (exited)` is normal for the lifecycle oneshot; use doctor/container health/logs for readiness. FreshClam may need time to refresh signatures.

## 3. Serve the existing NAS site through Web Station

The site already lives at `\\four-nas\local-share\four-media\media-hub\site`. No ZIP upload or second copy under `web` is required.

In DSM, select that folder as the static service's document root, using its actual NAS volume path: `<actual-volume>/local-share/four-media/media-hub/site`. Do not serve the whole project or shared-folder root. Confirm the portal maps to this service and the `http` group can traverse parents and read these assets.

From Windows, verify the expected files:

```powershell
$siteRoot = '\\four-nas\local-share\four-media\media-hub\site'
'index.html', 'styles.css', 'security.js', 'assets' | ForEach-Object {
  $assetPath = Join-Path $siteRoot $_
  if (-not (Test-Path -LiteralPath $assetPath)) { throw "Missing site asset: $assetPath" }
}
```

Open the recorded Web Station HTTP(S) URL. Six shortcuts and the four-security section should appear; unavailable reporting is expected until publication. An SMB path or `file://` view is not the website URL. The page fetches `data/security/status.json` from the same HTTP origin.

Create `site/data/security` if needed and preserve it when updating assets. Do not publish the sibling four-security repository, credentials, tests, `.git`, or SQLite files. The NAS projects remain the source locations; updates to those projects do not automatically update the staged Pi release.

## 4. Configure the report mount and publisher

Now that migration has created `/etc/four-security`, on the Pi:

```bash
sudo install -d -m 0755 /mnt/four-security/reports
sudoedit /etc/four-security/report-smb.credentials
sudo chown root:root /etc/four-security/report-smb.credentials
sudo chmod 0600 /etc/four-security/report-smb.credentials
```

Enter the separate report-only account in the editor, never as shell arguments:

```ini
username=YOUR_REPORT_ONLY_DSM_USER
password=YOUR_REPORT_ONLY_DSM_PASSWORD
```

Use `sudoedit /etc/fstab` to add exactly one entry with your verified report SMB source. The report directory is `local-share/four-media/media-hub/site/data/security`, inside the existing NAS site. Escape spaces using fstab syntax when needed. Keep the media entry separate and `ro`.

```fstab
//192.168.4.46/local-share/four-media/media-hub/site/data/security /mnt/four-security/reports cifs credentials=/etc/four-security/report-smb.credentials,rw,vers=3.0,uid=997,gid=983,file_mode=0640,dir_mode=0750,nosuid,nodev,noexec,_netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=15s 0 0
```

```bash
sudo systemctl daemon-reload
sudo systemctl start "$(systemd-escape --path --suffix=mount /mnt/four-security/reports)"
findmnt -T /mnt/four-security/reports -o SOURCE,TARGET,FSTYPE,OPTIONS
findmnt -T /mnt/four-security/downloads -o SOURCE,TARGET,FSTYPE,OPTIONS
sudo test -e /etc/four-security/publisher.json || sudo install -o root -g 983 -m 0640 /opt/four-security/config/publisher.json.example /etc/four-security/publisher.json
sudoedit /etc/four-security/publisher.json
```

Set publisher `source` to the SMB subdirectory used in fstab. Leave other fields at release defaults. Findmnt's `//host/share[/subdirectory]` display is accepted as equivalent to `//host/share/subdirectory`. Different sources/targets or local fallback directories are refused.

Check effective UID write/rename/delete access using a disposable file:

```bash
sudo setpriv --reuid=997 --regid=983 --clear-groups python3 - <<'PY'
import os, tempfile
from pathlib import Path
root = Path('/mnt/four-security/reports')
fd, name = tempfile.mkstemp(prefix='.four-security-access-', dir=root)
target = name + '.renamed'
try:
    with os.fdopen(fd, 'w') as stream:
        stream.write('Disposable report permission check\n')
    os.replace(name, target)
finally:
    Path(name).unlink(missing_ok=True)
    Path(target).unlink(missing_ok=True)
PY
```

Verify separately in DSM that this account cannot write outside reports, and that Web Station can read newly created reports. Client `file_mode` does not replace server ACLs.

Install and run once:

```bash
sudo install -m 0644 /opt/four-security/systemd/four-security-publish.service /etc/systemd/system/four-security-publish.service
sudo install -m 0644 /opt/four-security/systemd/four-security-publish.timer /etc/systemd/system/four-security-publish.timer
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/four-security.service /etc/systemd/system/four-security-publish.service /etc/systemd/system/four-security-publish.timer
sudo systemctl start four-security-publish.service
sudo journalctl -u four-security-publish.service -n 40 --no-pager
```

Open `<SITE_URL>/data/security/status.json` and compare real timestamps, run values and paths with the page/CLI. A valid never-scanned schema reports no scan; missing/uninitialized databases fail publication. Normal scanner startup initializes schema without starting a scan.

Once the one-shot succeeds:

```bash
sudo systemctl enable --now four-security-publish.timer
sudo systemctl list-timers four-security-publish.timer --all
```

The timer waits 30 seconds after completion, never overlaps itself and retries after failure. Service timeout is 25 seconds. OS-level uninterruptible CIFS stalls can outlast user-space timeouts; they remain confined to the publisher, not the scanner. A failure retains the previous valid report.

## 5. Acceptance, schedules, and cleanup

Record release/image, snapshot, portal URL, date and pass/fail evidence:

| Check | Expected |
| --- | --- |
| Rename/data | New hostname/project/binds; old jobs stopped; prior findings/times/cache eligibility preserved |
| Permissions | Media read-only; publisher can replace reports but cannot alter media/site code; Web Station reads reports |
| CLI versus page | Run ID, completion time, duration, attempts, cached results and findings agree |
| Live progress | A known benign targeted scan updates the page while retaining previous completed metrics |
| Coverage/history | Limits/warnings/errors distinct from detections; real history excludes discovery/dry runs; no full-library-clean assertion |
| Outage/recovery | Stop timer and service; page flags publication older than two minutes; restart timer and verify recovery |
| Write/mount failure | One-shot publication fails, previous JSON remains valid and scanning continues; restore settings after the test |
| Layout/load | All shortcuts, desktop/mobile layout and Jellyfin playback remain usable; observe Pi RAM/CPU |
| Reboot | Reconnect by IP; verify hostname, mounts, health, schedules and fresh publication |

For a benign scan, replace the example before running `sudo /opt/four-security/suite scan --target '/mnt/four-security/downloads/media/REPLACE_WITH_KNOWN_BENIGN_FILE.mkv'`. Newly observed files may need 900 seconds to stabilize. Exit 1 can mean findings; inspect results. Detection tests use disposable harmless fixtures, never live malware on the NAS.

For an outage test, stop both units so an in-flight publication cannot finish unnoticed:

```bash
sudo systemctl stop four-security-publish.timer four-security-publish.service
```

After acceptance, restore only the original intervals from the migration journal using `sudoedit /opt/four-security/.env`. Keep zero if previously zero; do not duplicate keys or introduce a new cadence. Apply with `sudo systemctl restart four-security.service`, run `sudo /opt/four-security/suite doctor`, and inspect startup logs. Restart resets elapsed-interval countdowns.

If startup at boot was previously enabled, restore it with `sudo systemctl enable four-security.service`; otherwise leave it disabled unless deliberately choosing boot startup. Re-enable publication after tests using `sudo systemctl enable --now four-security-publish.timer`. IDS still requires separate traffic-capture validation.

After acceptance/reboot, preview exact archive commands:

```bash
sudo python3 /opt/four-security/scripts/migrate-to-four-security.py --cleanup-preview /var/backups/four-security-migration/ACTUAL_SNAPSHOT
```

Use the actual snapshot path. The command prints, but does not run, moves of unchanged inventoried legacy unit definitions/overrides and a recognized legacy CLI symlink into the private snapshot. Review/run those exact commands. Active/enabled/changed units cause refusal. Source/data/config, volumes, images and backups are retained for rollback. Historical backups keep original names.

## Recovery and routine commands

Undo migration using the printed snapshot, **not** ordinary `suite rollback`:

```bash
sudo python3 /opt/four-security/scripts/migrate-to-four-security.py --rollback /var/backups/four-security-migration/ACTUAL_SNAPSHOT
```

Rollback stops new jobs, archives new state, unmounts new mounts, restores the suite media entry while preserving unrelated fstab additions, restores hostname/account names/unit enablement, and restarts previously running legacy services. It uses retained stopped legacy directories: do not edit/remove them before retiring rollback. Interrupted native scans are not rerun. Conflicting later hostname/hosts/config changes require reconciliation. New history is archived, not automatically merged into old state. The page may remain deployed showing unavailable/outdated reports; clear old JSON deliberately if desired.

Disable reporting alone:

```bash
sudo systemctl disable --now four-security-publish.timer
sudo systemctl stop four-security-publish.service
```

Everyday commands:

```bash
sudo systemctl status four-security.service --no-pager
sudo /opt/four-security/suite doctor
sudo /opt/four-security/suite alerts
sudo /opt/four-security/suite logs
sudo systemctl list-timers four-security-publish.timer --all
sudo journalctl -u four-security-publish.service -n 40 --no-pager
```

`suite stop`, backup, update and restore stop publication as well as containers. An enabled publisher timer restarts with `suite start`. Backups include publisher config/credentials beneath `/etc/four-security`; keep snapshots private and match them to release source.

Troubleshooting: 404 usually means document-root/SMB mapping; 403 means Web Station read ACLs; publication failures mean config, DB, mount or UID access. The journal logs error type without credentials/paths/evidence. Compare configuration locally; never paste passwords into chat. Never-scanned, stale scan and stale publication are distinct states. Reporting adds no deletion/quarantine, browser scan controls, or external messages.
