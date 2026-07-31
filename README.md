# Warrior Control Server

Render-ready Django control API for the desktop app. The current v1.6.1 EXE is
not modified by this project yet. It will be wired to the deployed URL in the
next step.

## Security and request flow

1. The desktop app calls `/api/v1/ip/` to learn the same public IPv4 the
   control server observes.
2. Before showing its main window, it POSTs that IPv4 to `/api/v1/bootstrap/`.
3. The app also sends a stable, non-secret device ID so systems behind the
   same office NAT can be distinguished.
4. The server independently reads the real source IPv4. On Render this is the
   first value in `X-Forwarded-For` when `TRUST_PROXY_HEADERS=1`.
5. Reported and observed IPv4 must match, and the IPv4 + device ID must have
   an active `ClientAccess` row. A blank device ID is an explicit IP-only row.
6. Only then is the encrypted configuration bundle decrypted and returned.
7. The response also includes provider/country metadata and a short-lived,
   IP-bound signed bearer token.
8. The app downloads the selected encrypted-at-rest country TXT through
   `/api/v1/proxies/<provider>/<country>/` using that bearer token.

Denied responses are intentionally generic. Configuration and proxy content
are never written to application logs. Successful responses send
`Cache-Control: no-store` and must be used only over HTTPS.

IP whitelisting is an access gate, not a replacement for transport security.
If multiple PCs share one office NAT IPv4, create one ClientAccess row per
stable device ID. The device ID distinguishes systems but is not a secret; a
future per-install activation credential can add stronger authentication.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DEBUG='1'
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver
```

Open `http://127.0.0.1:8000/admin/` and create records in this order:

1. Config bundle: paste a JSON object containing every former
   `warrior_config.txt` value.
2. Client access: whitelist the public IPv4, choose bundle, office name, and
   system number.
3. Providers: use only public codes such as P1, P2, and so on.
4. Proxy country files: paste each country TXT into the encrypted content box.

Example configuration JSON keys:

```json
{
  "APP_API_KEY": "...",
  "APP_BASE_URL": "http://127.0.0.1:54032",
  "APP_START_URL": "...",
  "WARRIOR_API_KEY": "..."
}
```

`OFFICE_NAME` and `SYSTEM_NUMBER` are overwritten from the matching client row,
so they can differ by office/system while sharing one bundle.

## API contract

Observed public IPv4:

```http
GET /api/v1/ip/
```

Bootstrap request:

```http
POST /api/v1/bootstrap/
Content-Type: application/json

{"reported_ipv4":"203.0.113.10","device_id":"stable-device-hash","app_version":"1.6.1"}
```

Catalog download:

```http
GET /api/v1/proxies/P1/US/
Authorization: Bearer <bootstrap access_token>
X-Device-ID: stable-device-hash
```

No API secret or proxy credential belongs in a URL/query string.

## Import the former configuration

An existing key/value file can be encrypted into a bundle without printing any
values:

```powershell
python manage.py import_warrior_config C:\secure\warrior_config.txt --name Office --bundle-version 1
```

Verify the bundle in admin, then securely delete the plaintext source. Never
commit that file to Git.

## Bulk provider/country import

Use folders such as `catalog_seed/P1/US__United States.txt`, then run:

```powershell
python manage.py import_proxy_catalog catalog_seed --disable-missing
```

Do not commit real credential TXT files to a public repository. Render's normal
filesystem is ephemeral; persistent application data belongs in PostgreSQL.

## Render deployment

1. Put this folder in a private Git repository.
2. In Render, create a Blueprint from `render.yaml`.
3. After deployment, open Render Shell and run:
   `python manage.py createsuperuser`.
4. Open `https://<service>.onrender.com/admin/` and enter your data.
5. Test `/healthz/` and then provide the base URL for the desktop integration.

Never rotate `CONFIG_ENCRYPTION_SECRET` without first re-encrypting or exporting
the stored data: changing it makes existing encrypted bundles unreadable.

The Blueprint uses PostgreSQL because Render's default service filesystem is
ephemeral. Production secrets are generated as environment variables, `DEBUG`
is off, and Django secure-cookie/HSTS/HTTPS settings are enabled.

## Swagger and Postman

With the local server running, open `http://127.0.0.1:8000/docs/` for interactive
Swagger UI. The raw OpenAPI 3.1 schema is at `/openapi.json`. Import
`Warrior-Control-API.postman_collection.json` into Postman and run its four
requests in order. For local testing, create a ClientAccess row matching
`127.0.0.1` and the collection's `device_id`; on the deployed server use the
actual public IPv4 returned by `/api/v1/ip/`.
