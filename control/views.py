from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import logging
import re
import secrets
from typing import Any

from datetime import timedelta, timezone as datetime_timezone

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.db.models import Prefetch, Q
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import (
    BootstrapAudit, ClientAccess, ExtensionPackage, ProfileActivity, ProfileDomainActivity, Provider, ProxyCountryFile,
    ProfileCreateLease, ProfileCreateQueue, ProxyGenerationJob, ProxyReservation,
    ProxyRegionCatalog,
)


# The currently deployed desktop client still expects the server to return the
# same number of proxy reservations that it submitted.  Keep the upper bound
# at the API's normal validation limit for this diagnostic release; the client
# side cap will be reintroduced once the rebuilt EXE is deployed.
MAX_PROFILES_PER_REQUEST = 50
from .proxy_jobs import get_or_create_pool_target, reserve_pool_proxies, reserve_static_proxies
from .tasks import queue_refill_proxy_pool
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
    active_regions = ProxyRegionCatalog.objects.filter(active=True).only(
        "provider_id", "country_code", "region_code", "region_name"
    )
    providers = Provider.objects.filter(active=True).prefetch_related(
        Prefetch("country_files", queryset=active_files),
        Prefetch("region_catalog", queryset=active_regions),
    )
    result: list[dict[str, Any]] = []
    for provider in providers:
        country_files = list(provider.country_files.all())
        if not country_files:
            continue
        regions_by_country: dict[str, list[dict[str, str]]] = {}
        if provider.code in {"P1", "P2"}:
            for region in provider.region_catalog.all():
                regions_by_country.setdefault(region.country_code, []).append(
                    {
                        "id": region.region_code,
                        "name": region.region_name,
                    }
                )
        result.append({
            "id": provider.code,
            "name": provider.display_name,
            "countries": [
                {
                    "id": row.country_code,
                    "name": row.country_name,
                    "version": row.version,
                    "sha256": row.content_sha256,
                    "regions": regions_by_country.get(row.country_code, []),
                }
                for row in country_files
            ],
        })
    return result


@require_GET
def home(request: HttpRequest) -> HttpResponse:
    return render(request, "control/home.html")


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
    # Rate-limit each authorized device independently. Multiple office PCs
    # commonly share the same public/NAT IP and must not consume one quota.
    rate_key = f"{observed_ip}:{access_ip}:{device_id or '<no-device-id>'}"
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

    if settings.LOCAL_TESTING_MODE:
        # The local test server is bound to loopback and intentionally uses its
        # first active client/config as a disposable sandbox.  This avoids
        # copying production device/IP allow-list data into the local SQLite DB.
        client = (
            ClientAccess.objects.select_related("config_bundle")
            .filter(active=True, config_bundle__active=True)
            .order_by("pk")
            .first()
        )
    else:
        client = (
            ClientAccess.objects.select_related("config_bundle")
            .filter(device_id=device_id)
            .filter(Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True))
            .distinct()
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

    group_id = client.config_bundle.browser_group_id.strip()
    group_name = client.config_bundle.browser_group_name.strip() or "Testing"
    profile_name = client.profile_name.strip() or client.name.strip()
    config["OFFICE_NAME"] = client.office_name
    config["SYSTEM_NUMBER"] = client.system_number
    config["BROWSER_GROUP_ID"] = group_id
    config["BROWSER_GROUP_NAME"] = group_name
    config["DEVICE_PROFILE_NAME"] = profile_name
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
            "assignment": {
                "browser_group_id": group_id,
                "browser_group_name": group_name,
                "profile_name": profile_name,
            },
            "catalog": {"providers": _catalog(), "extensions": [
                {"id": item.pk, "name": item.name, "filename": item.filename,
                 "version": item.version, "sha256": item.package_sha256,
                 "is_top": item.is_top, "status": item.status}
                for item in ExtensionPackage.objects.exclude(package_ciphertext="")
            ]},
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
        client = ClientAccess.objects.select_related("config_bundle").filter(
            pk=token_payload.get("client_id"),
            device_id=device_id,
            active=True,
            config_bundle__active=True,
        ).filter(
            Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        ).distinct().get()
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
    client_query = ClientAccess.objects.select_related("config_bundle").filter(
        pk=token_payload.get("client_id"), active=True, config_bundle__active=True,
    )
    if not settings.LOCAL_TESTING_MODE:
        client_query = client_query.filter(device_id=device_id).filter(
            Q(ipv4=access_ip) | Q(allowed_ips__ipv4=access_ip, allowed_ips__active=True)
        ).distinct()
    client = client_query.get()
    if token_payload.get("config_version") != client.config_bundle.version:
        raise signing.BadSignature("Configuration changed")
    return client


def _proxy_protocol(value: str) -> str:
    prefix = str(value or "").strip().partition("://")[0].casefold()
    if "://" not in str(value or ""):
        return ""
    return {
        "http": "http",
        "https": "https",
        "socks5": "socks5",
        "socks5h": "socks5",
    }.get(prefix, "")


def _profile_lease_key(client: ClientAccess, group_id: str) -> str:
    """Return an account-and-group scoped key without storing the API key."""
    try:
        payload = client.config_bundle.get_payload()
    except Exception:
        payload = {}
    account_key = str(
        payload.get("APP_API_KEY")
        or payload.get("YSBROWSER_API_KEY")
        or payload.get("API_KEY")
        or ""
    ).strip()
    if account_key:
        account_scope = hashlib.sha256(account_key.encode("utf-8")).hexdigest()[:32]
    else:
        account_scope = f"bundle-{client.config_bundle_id}"
    return f"profile-create:{account_scope}:{group_id.strip()}"


def _lease_group_allowed(client: ClientAccess, group_id: str) -> bool:
    assigned = str(client.config_bundle.browser_group_id or "").strip()
    return bool(group_id and (not assigned or assigned == group_id))


@csrf_exempt
@require_POST
def acquire_profile_lease(request: HttpRequest) -> JsonResponse:
    """Join a FIFO queue and atomically reserve one YS group for a run."""
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        group_id = str(body.get("group_id") or "").strip()[:64]
        requested_count = min(50, max(1, int(body.get("requested_count") or 1)))
        request_token = str(body.get("request_token") or "").strip()[:96]
        if not _lease_group_allowed(client, group_id):
            raise ValueError("Invalid browser group assignment")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    # Five minutes covers proxy polling plus the YS add/list/open sequence;
    # a crashed process is released automatically after this deadline.
    lease_seconds = 300
    queue_seconds = 43200
    now = timezone.now()
    expires_at = now + timedelta(seconds=lease_seconds)
    queue_expires_at = now + timedelta(seconds=queue_seconds)
    key = _profile_lease_key(client, group_id)
    with transaction.atomic():
        ProfileCreateQueue.objects.filter(
            scope_key=key, status="queued", expires_at__lte=now,
        ).update(status="expired")
        if request_token:
            try:
                queue = ProfileCreateQueue.objects.select_for_update().get(
                    request_token=request_token, scope_key=key, client=client,
                )
            except ProfileCreateQueue.DoesNotExist:
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
            if queue.status in {"completed", "expired"}:
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
            if queue.status == "active" and queue.lease_token:
                lease = ProfileCreateLease.objects.filter(
                    lease_key=key, owner_token=queue.lease_token,
                ).first()
                if lease and lease.expires_at > now:
                    return _json_response({"allowed": True, "lease_id": lease.owner_token, "group_id": group_id, "lease_seconds": lease_seconds})
                # This request already owned a lease and then stopped renewing
                # it.  Re-queuing the old row at its original FIFO position
                # leaves a dead request at the head for up to twelve hours.
                # Expire it and make the caller submit a fresh request instead.
                if lease:
                    lease.delete()
                queue.status = "expired"
                queue.lease_token = ""
                queue.expires_at = now
                queue.save(update_fields=("status", "lease_token", "expires_at", "updated_at"))
                return _json_response({"allowed": False, "message": "Profile request expired. Please try again."}, status=410)
        else:
            queue = ProfileCreateQueue.objects.create(
                scope_key=key,
                request_token=secrets.token_urlsafe(48),
                client=client,
                group_id=group_id,
                requested_count=requested_count,
                status="queued",
                expires_at=queue_expires_at,
            )

        lease = ProfileCreateLease.objects.select_for_update().filter(lease_key=key).first()
        if lease and lease.expires_at <= now:
            # A crashed client must leave the queue completely.  Re-queuing its
            # active row creates a permanent FIFO blocker because that client
            # will never poll its request token again.
            ProfileCreateQueue.objects.filter(
                scope_key=key, status="active", lease_token=lease.owner_token,
            ).update(status="expired", lease_token="", expires_at=now)
            lease.delete()
            lease = None

        head = ProfileCreateQueue.objects.select_for_update().filter(
            scope_key=key, status="queued", expires_at__gt=now,
        ).order_by("created_at", "pk").first()
        if lease or not head or head.pk != queue.pk:
            position = 1
            if head and head.pk != queue.pk:
                position = 1 + ProfileCreateQueue.objects.filter(
                    scope_key=key, status="queued", expires_at__gt=now,
                    created_at__lt=queue.created_at,
                ).count()
            return _json_response({
                "allowed": False,
                "queued": True,
                "request_token": queue.request_token,
                "position": position,
                "retry_after": 5,
                "message": "Your profile request is queued for this browser group.",
                "group_id": group_id,
            })

        owner_token = secrets.token_urlsafe(48)
        lease = ProfileCreateLease.objects.create(
            lease_key=key,
            owner_token=owner_token,
            client=client,
            group_id=group_id,
            requested_count=queue.requested_count,
            expires_at=expires_at,
        )
        queue.status = "active"
        queue.lease_token = owner_token
        queue.expires_at = expires_at
        queue.save(update_fields=("status", "lease_token", "expires_at", "updated_at"))
    return _json_response({
        "allowed": True,
        "lease_id": lease.owner_token,
        "group_id": group_id,
        "lease_seconds": lease_seconds,
    })


@csrf_exempt
@require_POST
def release_profile_lease(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
        body = json.loads(request.body.decode("utf-8"))
        group_id = str(body.get("group_id") or "").strip()[:64]
        lease_id = str(body.get("lease_id") or "").strip()[:96]
        if not lease_id or not _lease_group_allowed(client, group_id):
            raise ValueError("Invalid profile lease")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    key = _profile_lease_key(client, group_id)
    deleted, _ = ProfileCreateLease.objects.filter(
        lease_key=key, owner_token=lease_id, client=client,
    ).delete()
    ProfileCreateQueue.objects.filter(
        scope_key=key, lease_token=lease_id, client=client,
    ).update(status="completed", lease_token="")
    return _json_response({"allowed": bool(deleted), "released": bool(deleted)})


def _job_payload(job: ProxyGenerationJob) -> dict[str, Any]:
    reservations = job.reservations.order_by("reserved_at", "pk")
    proxies = []
    for item in reservations:
        value = item.get_proxy()
        proxies.append({
            "reservation_id": item.pk,
            "proxy": value,
            "protocol": _proxy_protocol(value),
            "provider": item.provider_code,
            "country": item.country_code,
            "region": item.region,
            "city": item.city,
        })
    return {
        "id": job.pk,
        "status": job.status,
        "submitted_count": job.submitted_count,
        "requested_count": job.requested_count,
        "candidate_count": max(
            int(job.requested_count),
            int(getattr(job, "candidate_count", 1) or 1),
        ),
        "max_profiles_per_request": MAX_PROFILES_PER_REQUEST,
        "was_capped": job.submitted_count > job.requested_count,
        "ready_count": job.ready_count,
        "error": job.error,
        "proxies": proxies,
    }


@require_GET
def extension_package(request: HttpRequest, package_id: int) -> HttpResponse:
    try:
        _authenticated_client(request)
        package = ExtensionPackage.objects.get(pk=package_id)
        raw = package.get_package()
        if not raw:
            raise ExtensionPackage.DoesNotExist
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist, ExtensionPackage.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)
    response = HttpResponse(raw, content_type="application/zip")
    response["Content-Disposition"] = f'attachment; filename="{package.filename}"'
    response["X-Content-SHA256"] = package.package_sha256
    response["Cache-Control"] = "no-store"
    return response


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
        submitted_count = int(body.get("count") or 1)
        requested_count = submitted_count
        candidate_count = int(
            body.get("candidate_count") or requested_count
        )
        if region.casefold() in {"any", "all", "random"}:
            region = ""
        if city.casefold() in {"any", "all", "random"}:
            city = ""
        if (
            not provider_code
            or not country_code
            or not 1 <= submitted_count <= MAX_PROFILES_PER_REQUEST
            or not requested_count <= candidate_count <= 50
        ):
            raise ValueError("Invalid proxy request")
        city = ""
        if provider_code not in {"P1", "P2"}:
            region = ""
        elif region and not ProxyRegionCatalog.objects.filter(
            provider__code=provider_code,
            provider__active=True,
            country_code=country_code,
            region_code=region,
            active=True,
        ).exists():
            raise ValueError("Unsupported provider region")
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            signing.BadSignature, signing.SignatureExpired, ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    with transaction.atomic():
        job = ProxyGenerationJob.objects.create(
            client=client, provider_code=provider_code, country_code=country_code,
            region=region, city=city, submitted_count=submitted_count,
            requested_count=requested_count,
            candidate_count=candidate_count,
            status="queued",
        )
        reservations = reserve_pool_proxies(
            client=client, job=job, provider_code=provider_code, country_code=country_code, region=region, city=city,
        )
        if len(reservations) < candidate_count:
            reservations += reserve_static_proxies(
                client=client, job=job, provider_code=provider_code, country_code=country_code, region=region, city=city,
            )
        job.ready_count = len(reservations)
        if job.ready_count >= candidate_count:
            job.status = "ready"
        elif job.ready_count:
            job.status = "partial"
        else:
            # The background pool worker will attach ready sessions to this job.
            job.status = "waiting_generation"
        job.save(update_fields=("ready_count", "status", "updated_at"))
        if settings.CELERY_BROKER_URL:
            target = get_or_create_pool_target(
                client=client, provider_code=provider_code,
                country_code=country_code, region=region, city=city,
            )
            transaction.on_commit(
                lambda target_id=target.pk: queue_refill_proxy_pool(target_id)
            )
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


_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalized_domain(value: Any) -> str:
    raw = str(value or "").strip().casefold().rstrip(".")
    if not raw or len(raw) > 253:
        raise ValueError("Invalid domain")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if any(character in raw for character in "/\\?#@:"):
        raise ValueError("Only a hostname is accepted")
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain") from exc
    labels = domain.split(".")
    if not labels or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain")
    return domain


def _activity_datetime(value: Any) -> Any:
    parsed = parse_datetime(str(value or "").strip())
    if parsed is None:
        raise ValueError("Invalid activity timestamp")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, datetime_timezone.utc)
    return parsed


@csrf_exempt
@require_POST
def profile_domains(request: HttpRequest) -> JsonResponse:
    try:
        client = _authenticated_client(request)
    except (ValueError, signing.BadSignature, signing.SignatureExpired,
            ClientAccess.DoesNotExist):
        return _json_response({"allowed": False, "message": "Access denied."}, status=403)

    try:
        body = json.loads(request.body.decode("utf-8"))
        session_id = str(body.get("session_id") or "").strip()
        profile_id = str(body.get("profile_id") or "").strip()[:128]
        if not _SESSION_ID_RE.fullmatch(session_id) or not profile_id:
            raise ValueError("Invalid profile session")
        session_started_at = _activity_datetime(body.get("session_started_at"))
        session_ended_at = _activity_datetime(body.get("session_ended_at"))
        if session_ended_at < session_started_at:
            raise ValueError("Invalid profile session interval")
        raw_domains = body.get("domains")
        if not isinstance(raw_domains, list) or not 1 <= len(raw_domains) <= 2000:
            raise ValueError("Invalid domain batch")
        job_id = body.get("job_id")
        reservation_id = body.get("reservation_id")
        job = (
            ProxyGenerationJob.objects.get(pk=job_id, client=client)
            if job_id else None
        )
        reservation = (
            ProxyReservation.objects.get(pk=reservation_id, client=client)
            if reservation_id else None
        )
        normalized: dict[str, dict[str, Any]] = {}
        for item in raw_domains:
            if not isinstance(item, dict):
                raise ValueError("Invalid domain row")
            domain = _normalized_domain(item.get("domain"))
            first_visited_at = _activity_datetime(item.get("first_visited_at"))
            last_visited_at = _activity_datetime(item.get("last_visited_at"))
            if last_visited_at < first_visited_at:
                raise ValueError("Invalid domain interval")
            visit_count = max(1, min(100000, int(item.get("visit_count") or 1)))
            existing = normalized.get(domain)
            if existing is None:
                normalized[domain] = {
                    "first_visited_at": first_visited_at,
                    "last_visited_at": last_visited_at,
                    "visit_count": visit_count,
                }
            else:
                existing["first_visited_at"] = min(
                    existing["first_visited_at"], first_visited_at
                )
                existing["last_visited_at"] = max(
                    existing["last_visited_at"], last_visited_at
                )
                existing["visit_count"] = min(
                    100000, existing["visit_count"] + visit_count
                )
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
            ProxyGenerationJob.DoesNotExist, ProxyReservation.DoesNotExist):
        return _json_response(
            {"allowed": True, "message": "Invalid domain activity payload."},
            status=400,
        )

    group_id = str(body.get("group_id") or "")[:64]
    profile_name = str(body.get("profile_name") or "")[:160]
    browser_id = str(body.get("browser_id") or "")[:64]
    created = 0
    updated = 0
    with transaction.atomic():
        for domain, activity in normalized.items():
            _row, was_created = ProfileDomainActivity.objects.update_or_create(
                client=client,
                profile_id=profile_id,
                session_id=session_id,
                domain=domain,
                defaults={
                    "job": job,
                    "reservation": reservation,
                    "group_id": group_id,
                    "profile_name": profile_name,
                    "browser_id": browser_id,
                    "first_visited_at": activity["first_visited_at"],
                    "last_visited_at": activity["last_visited_at"],
                    "visit_count": activity["visit_count"],
                    "session_started_at": session_started_at,
                    "session_ended_at": session_ended_at,
                },
            )
            if was_created:
                created += 1
            else:
                updated += 1
        if reservation is not None:
            reservation.profile_id = profile_id
            reservation.profile_name = profile_name
            reservation.save(update_fields=("profile_id", "profile_name"))
    return _json_response(
        {
            "allowed": True,
            "accepted": len(normalized),
            "created": created,
            "updated": updated,
        },
        status=201,
    )
