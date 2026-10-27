# NAS dashboard source

`site/` contains the static Web Station application launcher, file-scan report and
Suricata alert dashboard. Deploy the contents to the existing NAS root
`four-media/media-hub/site`. The live root is a separate shared folder; update this
versioned source with future site changes as well.

The page reads `data/security/status.json` from the same origin. That runtime file
is published by the Pi and deliberately excluded from this source tree. Preserve the
NAS data/security directory during asset deployment. Do not serve the security
repository itself as a web root. No external JavaScript, API credentials or backend
web server is required.

```bash
node --test dashboard/tests/*.test.cjs
```

See [file reporting](../docs/REPORTING.md), [network alerts](../docs/IDS-DASHBOARD.md)
and the [Suricata POC](../poc/suricata8/README.md) for configuration and limits.
Anyone reaching the dashboard can read its published scan paths and alert addresses.
