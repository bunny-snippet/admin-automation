# Warrior: OPTIX-only YS catalog sync

This source port adds metadata delivery for updated OPTIX clients only. Deploying
the server does not install new client code. Legacy **I am the best** clients and
their existing proxy, office, IP, activation and assignment behavior are unchanged.

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

## Deployment

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

Configure a dedicated worker using the existing private Redis broker:

```bash
./.venv/bin/celery -A controlserver worker -Q catalog-sync --concurrency=1 --loglevel=INFO --hostname='warrior-catalog@%h'
```

Restart the existing Celery beat scheduler to load the new schedule; run exactly
one beat for this deployment, not a second scheduler. If no beat exists, configure
`./.venv/bin/celery -A controlserver beat --loglevel=INFO` in the process manager.
Web-only deployment is insufficient. Catalog-worker startup does not enqueue proxy
generation; existing `proxy-jobs` worker startup behavior is preserved.

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
