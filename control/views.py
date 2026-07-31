from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.db.models import Prefetch
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import BootstrapAudit, ClientAccess, Provider, ProxyCountryFile
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
        observed_ip = observed_client_ip(request)
        if ipaddress.ip_address(observed_ip).version != 4:
            return _denied("ipv4-required", observed_ip=observed_ip)
        if _rate_limited(observed_ip):
            return _denied("rate-limited", observed_ip=observed_ip, status=429)
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

    if settings.REQUIRE_REPORTED_IP_MATCH and reported_ip != observed_ip:
        return _denied(
            "ip-mismatch",
            observed_ip=observed_ip,
            reported_ip=reported_ip,
            app_version=app_version,
            device_id=device_id,
        )

    client = (
        ClientAccess.objects.select_related("config_bundle")
        .filter(ipv4=observed_ip, device_id=device_id)
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
        "ip": observed_ip,
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
            "warrior_config": config,
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
        observed_ip = observed_client_ip(request)
        device_id = str(request.META.get("HTTP_X_DEVICE_ID", "")).strip()[:128]
        token_payload = signing.loads(
            _bearer_token(request),
            salt=TOKEN_SALT,
            max_age=settings.BOOTSTRAP_TOKEN_MAX_AGE,
        )
        if token_payload.get("ip") != observed_ip:
            raise signing.BadSignature("IP changed")
        if token_payload.get("device_id", "") != device_id:
            raise signing.BadSignature("Device changed")
        client = ClientAccess.objects.select_related("config_bundle").get(
            pk=token_payload.get("client_id"),
            ipv4=observed_ip,
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
