from __future__ import annotations

import hmac
import ipaddress
import json
import logging
from typing import Any

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.db.models import Prefetch
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import (
    BootstrapAudit, ClientAccess, ProfileActivity, Provider, ProxyCountryFile,
    ProxyGenerationJob, ProxyReservation,
)
from .proxy_jobs import reserve_static_proxies
from .tasks import generate_proxy_job
from .openapi import OPENAPI_SCHEMA, SWAGGER_HTML


logger = logging.getLogger("control")
TOKEN_SALT = "warrior-control-catalog-v1"


def _json_response(payload: dict[str, Any], status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _normalized_ip(value: Any) -> str:
    parsed = ipaddress.ip_address(str(value or "").strip())
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    return str(parsed)


def observed_client_ip(request: HttpRequest) -> str:
    if settings.TRUST_PROXY_HEADERS:
        origin_secret = settings.CLOUDFLARE_ORIGIN_SECRET
        if origin_secret:
            supplied_secret = request.META.get(
                "HTTP_X_TUBELIGHT_ORIGIN_SECRET", ""
            )
            if not hmac.compare_digest(supplied_secret, origin_secret):
                raise ValueError("Untrusted origin request")
            cloudflare_ip = request.META.get("HTTP_CF_CONNECTING_IP", "")
            if not cloudflare_ip:
                raise ValueError("Cloudflare client IP missing")
            return _normalized_ip(cloudflare_ip)

        # Local/legacy deployments without the Cloudflare origin secret keep
        # the normal reverse-proxy fallbacks. Production kanikdev.xyz should
        # always configure the secret so spoofed IP headers are rejected.
        real_ip = request.META.get("HTTP_X_REAL_IP", "")
        if real_ip:
            return _normalized_ip(real_ip)
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return _normalized_ip(forwarded.split(",", 1)[0])
    return _normalized_ip(request.META.get("REMOTE_ADDR", ""))


def _rate_limited(ip_value: str) -> bool:
    limit = max(1, settings.BOOTSTRAP_RATE_LIMIT_PER_MINUTE)
    key = f"bootstrap-rate:{ip_value}:{int(timezone.now().timestamp()) // 60}"
    if cache.add(key, 1, timeout=75):
        return False
    try:
        return cache.incr(key) > limit
    except ValueError:
        return False


def _audit(
    *,
    observed_ip: str | None,
    reported_ip: str | None,
    allowed: bool,
    reason: str,
    app_version: str,
    device_id: str = "",
    client: ClientAccess | None = None,
) -> None:
    try:
        BootstrapAudit.objects.create(
            client=client,
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            device_id=device_id[:128],
            allowed=allowed,
            reason=reason[:80],
            app_version=app_version[:40],
        )
    except Exception:
        logger.exception("Could not write bootstrap audit event")


def _denied(
    reason: str,
    *,
    observed_ip: str | None = None,
    reported_ip: str | None = None,
    app_version: str = "",
    device_id: str = "",
    client: ClientAccess | None = None,
    status: int = 403,
) -> JsonResponse:
    _audit(
        observed_ip=observed_ip,
        reported_ip=reported_ip,
        allowed=False,
        reason=reason,
        app_version=app_version,
        device_id=device_id,
        client=client,
    )
    return _json_response(
        {"allowed": False, "message": "Access denied."},
        status=status,
    )


def _catalog() -> list[dict[str, Any]]:
    active_files = ProxyCountryFile.objects.filter(active=True).only(
        "provider_id", "country_code", "country_name", "version", "content_sha256"
    )
    providers = Provider.objects.filter(active=True).prefetch_related(
        Prefetch("country_files", queryset=active_files)
    )
    return [
        {
            "id": provider.code,
            "name": provider.display_name,
            "countries": [
                {
                    "id": row.country_code,
                    "name": row.country_name,
                    "version": row.version,
                    "sha256": row.content_sha256,
                }
                for row in provider.country_files.all()
            ],
        }
        for provider in providers
        if provider.country_files.all()
    ]


@require_GET
def healthz(_request: HttpRequest) -> JsonResponse:
    return _json_response({"ok": True})


@require_GET
def openapi_schema(_request: HttpRequest) -> JsonResponse:
    return JsonResponse(OPENAPI_SCHEMA)


@require_GET
def swagger_docs(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(SWAGGER_HTML, content_type="text/html; charset=utf-8")


@require_GET
def public_ipv4(request: HttpRequest) -> JsonResponse:
    try:
        observed_ip = observed_client_ip(request)
        if ipaddress.ip_address(observed_ip).version != 4:
            raise ValueError("IPv4 required")
    except ValueError:
        return _json_response(
            {"ok": False, "message": "IPv4 unavailable."},
            status=400,
        )
    return _json_response({"ok": True, "ipv4": observed_ip})


@csrf_exempt
@require_POST
def bootstrap(request: HttpRequest) -> JsonResponse:
    observed_ip: str | None = None
    reported_ip: str | None = None
    app_version = ""
    device_id = ""
    try:
        if settings.TRUST_APP_REPORTED_IPV4:
            # In approved app-reported mode the transport address is audit-only.
            # Do not require Cloudflare headers: the custom domain may be DNS-only.
            observed_ip = _normalized_ip(request.META.get("REMOTE_ADDR", ""))
        else:
            observed_ip = observed_client_ip(request)
        if ipaddress.ip_address(observed_ip).version != 4:
            return _denied("ipv4-required", observed_ip=observed_ip)
        body = json.loads(request.body.decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        reported_ip = _normalized_ip(body.get("reported_ipv4"))
        app_version = str(body.get("app_version") or "")
        device_id = str(body.get("device_id") or "").strip()[:128]
        if ipaddress.ip_address(reported_ip).version != 4:
            return _denied(
                "reported-ipv4-required",
                observed_ip=observed_ip,
                reported_ip=reported_ip,
                app_version=app_version,
            )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return _denied(
            "invalid-request",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            status=400,
        )

    access_ip = (
        reported_ip if settings.TRUST_APP_REPORTED_IPV4 else observed_ip
    )
    rate_key = f"{observed_ip}:{access_ip}"
    if _rate_limited(rate_key):
        return _denied(
            "rate-limited",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            status=429,
        )
    if (
        not settings.TRUST_APP_REPORTED_IPV4
        and settings.REQUIRE_REPORTED_IP_MATCH
        and reported_ip != observed_ip
    ):
        return _denied(
            "ip-mismatch",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
        )

    client = (
        ClientAccess.objects.select_related("config_bundle")
        .filter(ipv4=access_ip, device_id=device_id)
        .first()
    )
    if client is None:
        return _denied(
            "not-whitelisted",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
        )
    if not client.active or not client.config_bundle.active:
        return _denied(
            "inactive",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            client=client,
        )

    try:
        config = client.config_bundle.get_payload()
    except ValueError:
        logger.exception("Configuration decryption failed for bundle %s", client.config_bundle_id)
        return _denied(
            "config-unavailable",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
            client=client,
            status=503,
        )

    config["OFFICE_NAME"] = client.office_name
    config["SYSTEM_NUMBER"] = client.system_number
    token_payload = {
        "client_id": client.pk,
        "ip": access_ip,
        "ip_source": (
            "app-reported" if settings.TRUST_APP_REPORTED_IPV4 else "observed"
        ),
        "device_id": device_id,
        "config_version": client.config_bundle.version,
    }
    token = signing.dumps(token_payload, salt=TOKEN_SALT, compress=True)
    ClientAccess.objects.filter(pk=client.pk).update(last_seen_at=timezone.now())
    _audit(
        observed_ip=observed_ip,
        reported_ip=reported_ip,
        allowed=True,
        reason="allowed",
        app_version=app_version,
        device_id=device_id,
        client=client,
    )
    return _json_response(
        {
            "allowed": True,
            "schema_version": 1,
            "config_version": client.config_bundle.version,
            "expires_in": settings.BOOTSTRAP_TOKEN_MAX_AGE,
            "access_token": token,
            "tubelight_config": config,
            "catalog": {"providers": _catalog()},
        }
    )


def _bearer_token(request: HttpRequest) -> str:
    authorization = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise ValueError("Missing bearer token")
    return value.strip()


@require_GET
def proxy_file(request: HttpRequest, provider_code: str, country_code: str) -> JsonResponse:
    try:
        if settings.TRUST_APP_REPORTED_IPV4:
            observed_ip = _normalized_ip(request.META.get("REMOTE_ADDR", ""))
        else:
            observed_ip = observed_client_ip(request)
        device_id = str(request.META.get("HTTP_X_DEVICE_ID", "")).strip()[:128]
        if settings.TRUST_APP_REPORTED_IPV4:
            access_ip = _normalized_ip(
                request.META.get("HTTP_X_CLIENT_IPV4", "")
            )
            if ipaddress.ip_address(access_ip).version != 4:
                raise ValueError("Client IPv4 required")
        else:
            access_ip = observed_ip
        token_payload = signing.loads(
            _bearer_token(request),
            salt=TOKEN_SALT,
            max_age=settings.BOOTSTRAP_TOKEN_MAX_AGE,
        )
        if token_payload.get("ip") != access_ip:
            raise signing.BadSignature("IP changed")
        if token_payload.get("device_id", "") != device_id:
            raise signing.BadSignature("Device changed")
        client = ClientAccess.objects.select_related("config_bundle").get(
            pk=token_payload.get("client_id"),
            ipv4=access_ip,
            device_id=device_id,
            active=True,
            config_bundle__active=True,
        )
        if token_payload.get("config_version") != client.config_bundle.version:
            raise signing.BadSignature("Configuration changed")
        row = ProxyCountryFile.objects.select_related("provider").get(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            active=True,
        )
        content = row.get_content()
    except (
        ValueError,
        signing.BadSignature,
        signing.SignatureExpired,
        ClientAccess.DoesNotExist,
        ProxyCountryFile.DoesNotExist,
    ):
        return _json_response(
            {"allowed": False, "message": "Access denied."},
            status=403,
        )
    return _json_response(
        {
            "allowed": True,
            "provider": row.provider.code,
            "country": row.country_code,
            "version": row.version,
            "sha256": row.content_sha256,
            "content": content,
        }
    )


def _authenticated_client(request: HttpRequest) -> ClientAccess:
    """Validate the short-lived, IP and device-bound bootstrap token."""
    if settings.TRUST_APP_REPORTED_IPV4:
        access_ip = _normalized_ip(request.META.get("HTTP_X_CLIENT_IPV4", ""))
        if ipaddress.ip_address(access_ip).version != 4:
            raise ValueError("Client IPv4 required")
    else:
        access_ip = observed_client_ip(request)
    device_id = str(request.META.get("HTTP_X_DEVICE_ID", "")).strip()[:128]
    token_payload = signing.loads(_bearer_token(request), salt=TOKEN_SALT,
                                  max_age=settings.BOOTSTRAP_TOKEN_MAX_AGE)
    if token_payload.get("ip") != access_ip or token_payload.get("device_id", "") != device_id:
        raise signing.BadSignature("Client identity changed")
    client = ClientAccess.objects.select_related("config_bundle").get(
        pk=token_payload.get("client_id"), ipv4=access_ip, device_id=device_id,
        active=True, config_bundle__active=True,
    )
    if token_payload.get("config_version") != client.config_bundle.version:
        raise signing.BadSignature("Configuration changed")
    return client


def _job_payload(job: ProxyGenerationJob) -> dict[str, Any]:
    reservations = job.reservations.order_by("reserved_at", "pk")
    return {
        "id": job.pk,
        "status": job.status,
        "requested_count": job.requested_count,
        "ready_count": job.ready_count,
        "error": job.error,
        "proxies": [
            {
                "reservation_id": item.pk,
                "proxy": item.get_proxy(),
                "provider": item.provider_code,
                "country": item.country_code,
                "region": item.region,
                "city": item.city,
            }
            for item in reservations
        ],
    }


@csrf_exempt
@require_POST
def create_proxy_job(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        provider_code = str(body.get("provider") or "").strip().upper()
        country_code = str(body.get("country") or "").strip().upper()
        region = str(body.get("region") or "").strip()[:120]
        city = str(body.get("city") or "").strip()[:120]
        requested_count = int(body.get("count") or 1)
        if not provider_code or not country_code or not 1 <= requested_count <= 50:
            raise ValueError("Invalid proxy request")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    with transaction.atomic():
        job = ProxyGenerationJob.objects.create(
            client=client, provider_code=provider_code, country_code=country_code,
            region=region, city=city, requested_count=requested_count, status="queued",
        )
        reservations = reserve_static_proxies(
            client=client, job=job, provider_code=provider_code,
            country_code=country_code, region=region, city=city,
        )
        job.ready_count = len(reservations)
        if job.ready_count == job.requested_count:
            job.status = "ready"
        elif job.ready_count:
            job.status = "partial"
        else:
            # A worker will later try provider generation. The state is explicit
            # so the app can poll without silently treating this as completion.
            job.status = "waiting_generation"
        job.save(update_fields=("ready_count", "status", "updated_at"))
        if job.ready_count < job.requested_count:
            transaction.on_commit(lambda: generate_proxy_job.delay(job.pk))
    return _json_response({"allowed": True, "job": _job_payload(job)}, status=201)


@require_GET
def proxy_job_detail(request: HttpRequest, job_id: int) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        job = ProxyGenerationJob.objects.get(pk=job_id, client=client)
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist, ProxyGenerationJob.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    return _json_response({"allowed": True, "job": _job_payload(job)})


@csrf_exempt
@require_POST
def profile_activity(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        job_id = body.get("job_id")
        reservation_id = body.get("reservation_id")
        status = str(body.get("status") or "").strip()[:32]
        if not status:
            raise ValueError("Missing status")
        job = ProxyGenerationJob.objects.get(pk=job_id, client=client) if job_id else None
        reservation = ProxyReservation.objects.get(pk=reservation_id, client=client) if reservation_id else None
        urls = body.get("start_urls", [])
        if not isinstance(urls, list):
            raise ValueError("Invalid URLs")
        ProfileActivity.objects.create(
            client=client, job=job, reservation=reservation,
            group_id=str(body.get("group_id") or "")[:64],
            profile_name=str(body.get("profile_name") or "")[:160],
            profile_id=str(body.get("profile_id") or "")[:128], status=status,
            start_urls_json=json.dumps(urls)[:10000], detail=str(body.get("detail") or "")[:4000],
        )
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist,
            ProxyGenerationJob.DoesNotExist, ProxyReservation.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    return _json_response({"allowed": True}, status=201)
