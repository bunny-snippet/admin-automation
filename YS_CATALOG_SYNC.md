# Warrior: OPTIX-only YS catalog sync

This deployment delivers metadata to updated OPTIX clients only. Legacy **I am
the best** clients and their existing proxy, office, IP, activation and assignment
behavior are unchanged.

## Deployment status — 2026-09-06

Both Warrior/OPTIX and Dollar server deployments and their independent scheduled
metadata refreshes are live. Each has imported **19 common catalogs and 6 browser
version metadata rows**. Testing-channel component release **202609060101** is
published.

Dollar **0.2.0** supports the component bridge. Existing OPTIX **1.6.1** needs the
one-time **1.6.2** wrapper update to consume these components; that optional
installer rollout remains pending. Final PC activation has not been confirmed.
Server deployment or component publication is not proof of activation on a PC.

Catalog refreshes never automatically download or install browser binaries.
Private deployment backups and component-upload staging directories are excluded
from Git; existing private runtime data stays outside version control.

## Scope and safeguards

The dedicated catalog job runs at **08:00, 12:00, 16:00 and 20:00 Asia/Kolkata**.
It reads only the original YS common catalog and browser-version metadata endpoints:

- `POST https://admin.ysbrowser.com/api/common/getWebConfigValue`: empty form, no key.
- `POST https://admin.ysbrowser.com/api/aegisVersion/aegisCheck`: bounded pagination,
  original YS server-side `X-API-Key`.

The importer allowlists fingerprint data such as fonts, CPU, memory, screens and
OS metadata. It excludes `SecureJson`, `ipList`, routing, credentials, release HTML
and browser download URLs. No profiles, accounts, device data or proxy assignments
are uploaded. TLS verification stays enabled; redirects are refused. Response
size, nesting, schema, pagination and task runtime are bounded. DB leases prevent
overlapping writes, and each resource retains its last valid snapshot on failure.
Django admin **YS browser catalog sync status** shows read-only status/timestamps.

Browser versions are discovery only (`runtime_target=unverified`, `installable=false`).
A Windows-hosted binary is not evidence that its fingerprint target is desktop;
Android-emulating builds must remain separate. This job never downloads, installs
or executes binaries, changes the curated runtime policy, or signs releases.

## Deployment reference

Set only in this Warrior server's private environment:

```dotenv
YS_CATALOG_SYNC_ENABLED=true
YS_UPSTREAM_API_KEY=<original YS account key; never an OPTIX activation/B1 key>
```

After deploying, migrate before restarting web and worker services:

```bash
./.venv/bin/python manage.py migrate
./.venv/bin/python manage.py check
./.venv/bin/python manage.py sync_ys_catalogs
./.venv/bin/python manage.py sync_ys_catalogs --status
```

Migration `0042_browsercatalogsnapshot` follows Warrior's
`0041_clientaccess_migration_progress`; it only creates the catalog snapshot table.
The status command is read-only, with no YS call. Manual sync explicitly runs even
when scheduled sync is disabled; failure retains prior valid data and exits nonzero.
Missing/invalid upstream credentials may block browser metadata independently of
the unauthenticated common catalog.

## Standalone scheduling on the current Warrior deployment

Use the existing **bunny** account and `.venv/bin/python`. No new Redis, Celery
worker or beat is required. Do not start a full beat merely for this feature: it
would also schedule unrelated proxy maintenance.

```bash
cd /home/automation-exchange-ip/htdocs/warrior_control_server
.venv/bin/python deploy/install_ys_catalog_cron.py
.venv/bin/python deploy/install_ys_catalog_cron.py --install
.venv/bin/python deploy/install_ys_catalog_cron.py
```

Run these commands as bunny, never root. The default command is a read-only
check. `--install` privately backs up the full prior user crontab in
`tmp/ys-catalog-crontab-before-*.txt`, preserves every unrelated entry, updates
only the uniquely marked catalog block, and verifies the result. It refuses
ambiguous markers or a changed crontab rather than overwriting them. Do not
replace the whole user crontab with the small fragment. Backups may contain
private configuration; keep them local, mode 0600, and never commit them.

The installed minute-level shell guard checks `Asia/Kolkata`; it returns
immediately except at **08:00, 12:00, 16:00 and 20:00 IST**. Django therefore
runs only four times daily, regardless of the host cron timezone. No `CRON_TZ`
support is assumed. The equivalent UTC slots are **02:30, 06:30, 10:30, 14:30**,
but a direct `30 2,6,10,14 * * *` entry is safe only after confirming the cron
daemon uses UTC. Do not install both forms.

The runner uses a per-repo `flock`, a 720-second timeout and
`sync_ys_catalogs --scheduled`. Scheduled mode respects
`YS_CATALOG_SYNC_ENABLED=false` without requests or DB writes; normal manual
mode retains its explicit force behavior. The private log
`tmp/ys-catalog-sync.log` contains one short UTC timestamp/result/exit-code line
per attempted scheduled run. Raw Django output is suppressed; use admin or
`sync_ys_catalogs --status` for sanitized resource errors. A timeout/failure exits
nonzero; a live lock skips safely. Log volume is at most four normal lines/day;
use existing log retention controls if required.

No scheduled catch-up runs occur after downtime. Do not enable a second catalog
schedule through Celery at the same time. Existing proxy workers, cache,
office/IP policy and profile execution are untouched.

## Private client delivery

Only bootstrap requests explicitly identifying `client_product=optix` receive a
`browser_catalog_sync` descriptor. Legacy and version-inferred clients do not.
`GET /api/v1/browser-catalog/` requires a normal active, device/IP-bound bootstrap
token from an explicitly identified OPTIX bootstrap, and a stored OPTIX client
identity. Version inference alone does not authorize this endpoint; legacy tokens
remain unchanged. It returns schema 1, an opaque revision,
allowlisted catalogs, and discovery-only browser versions, with private/no-store
headers. An absent valid snapshot does not break bootstrap; catalog GET returns 503.

A signed OPTIX client/component update must first install the matching consumer.
After that, normal bootstrap/Reload can refresh metadata without a new installer.
Refresh must preserve local overrides, active profiles, office/access policy,
proxy routing and activation/B1 keys. The Glider relay change is separate.
