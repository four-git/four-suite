# Part 1 — Prepare the environment

Use this before [Part 2: deployment](DEPLOYMENT.md). The completed project files are now stored on the NAS at the locations below. This stage prepares hosting and permissions without stopping or renaming the existing scanner.

## Record the actual values

| Value | Expected / example |
| --- | --- |
| Pi SSH login | `YOUR_PI_USER@192.168.4.51`, with sudo |
| Pi platform | Debian 13 ARM64, working Docker/Compose |
| Current installation | `/opt/four-securitycenter`, `/etc/four-securitycenter`, `/var/lib/four-securitycenter` |
| NAS | `four-nas`, `192.168.4.46` |
| Media share | `//192.168.4.46/data`, read-only to scanner |
| Site project | `\\four-nas\local-share\four-media` |
| Security project / release source | `\\four-nas\local-share\four-security` |
| Website document root | `<actual-volume>/local-share/four-media/media-hub/site`; verify volume in DSM |
| Reports | `\\four-nas\local-share\four-media\media-hub\site\data\security` |
| Report SMB source | Example `//192.168.4.46/local-share/four-media/media-hub/site/data/security` |
| Website URL | Example `http://192.168.4.46:8099/`; choose an available portal port |
| Publisher DSM account | Separate account restricted to reports |

The UNC paths identify the existing NAS project folders; they do not identify the NAS volume or an HTTP URL. Verify the actual volume and portal port in DSM. The Pi IP and NAS hostname stay unchanged. Security code is staged from the NAS onto the Pi at `/opt/four-security`; active SQLite state and credentials stay on the Pi, not on SMB. The Pi hostname becomes `four-security` in Part 2. The GitHub remote is not renamed by this release.

## Prepare Web Station and folders

1. In DSM Package Center, install/open Web Station and packages it requires. This is a static site; PHP, a database, Docker hosting, and Node are unnecessary.
2. In File Station, use the existing `local-share/four-media/media-hub/site` folder as the document root. Create only its `data/security` subdirectory if missing. The checked layout has `index.html`, `styles.css`, `security.js`, and `assets/` directly in `site`. Do not point the portal at `local-share`, the four-media project root, or the four-security project: those contain source/docs and are not the public site.
3. In Web Station, create a **static website** service pointing at that root, then its web service portal using a free LAN HTTP port or suitable HTTPS portal. DSM versions label these pages Web Service, Web Portal, or Web Service Portal. Record the URL.
4. Give the `http` group read/traverse access to the root, files, and reports. Leave directory listings disabled. No website login is configured.
5. The completed assets already live on this NAS share, so no separate upload into a `web` folder is needed. Part 2 verifies the portal against these existing files. Do not publish a sample clean report; unavailable is correct until real publication.

Synology documents [hosting](https://kb.synology.com/en-id/DSM/tutorial/How_to_host_a_website_on_Synology_NAS), [portal configuration](https://kb.synology.com/index.php/en-us/DSM/help/WebStation/application_webserv_virtualhost?version=7), and [document-root permissions](https://kb.synology.com/en-us/DSM/tutorial/What_should_I_set_permissions_to_folders_for_websites). Use the menus for your installed DSM version.

## Separate publisher account

Create a DSM account whose effective permissions allow traversal to the report folder and read/write/create/rename/delete **inside that folder only**. Deny writes to media, page HTML/JavaScript, and other website folders. Keep the existing media-read account separate. Permit traversal through `local-share/four-media/media-hub/site` only as needed; do not expose or grant publisher write access to the sibling `local-share/four-security` project. The Web Station `http` group needs traversal of the same parent folders and read access to `site`, not broad read access to the entire shared folder.

Check group memberships and inherited ACLs. A parent shared-folder permission may need narrower child ACLs; a global deny that prevents traversal will not work. Verify effective permissions with disposable files, never by overwriting real page/media files. Ensure newly created reports inherit read access for Web Station's `http` group. Do not grant broad website writes to fix an ACL problem.

Keep the portal on the home network. Everyone who can reach it can read published findings and absolute paths. No router forwarding or external notification service is needed.

## Inspect the Pi — read-only Bash commands

```bash
hostnamectl
cat /etc/os-release
uname -m
sudo docker compose version
sudo systemctl list-unit-files 'four-securitycenter*'
sudo systemctl list-units --all 'four-securitycenter*'
sudo docker ps -a --filter label=com.docker.compose.project=four-securitycenter
findmnt -t cifs,autofs
df -h /opt /var
getent passwd 997
getent group 983
sudo grep -E '^(SCAN_INTERVAL_SECONDS|DISCOVER_INTERVAL_SECONDS)=' /opt/four-securitycenter/.env
```

The migrator targets the existing Docker installation at standard paths. It refuses conflicting destinations/identities and unexpected layouts. Native-only installations require a separately reviewed migration; do not bypass the rename using native setup options.

Allow space for a stopped backup and a second state copy; ClamAV signatures can be large. Reserve a maintenance window for migration and reboot checks. Scanning stops temporarily; NAS media applications are not intentionally stopped.

**Do not create `/etc/four-security`, `/var/lib/four-security`, or new Pi mount directories yet.** The migrator creates them and refuses conflicts. Enter report credentials only in Part 2. Existing media credentials stay unchanged.

Continue with [deployment](DEPLOYMENT.md) once hosting, folders, ACLs, Pi access and recorded values are ready.
