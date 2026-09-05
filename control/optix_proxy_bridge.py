"""Private OPTIX-to-Warrior proxy bridge.

Desktop clients never call this endpoint.  The separate OPTIX control server
uses a short-lived HMAC signature and Warrior maps the request to the existing
client record before reusing its normal pool, reservation and cooldown logic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.test.client import RequestFactory
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import ClientAccess


MAX_SKEW_SECONDS = 120


def _secret() -> bytes:
    return str(getattr(settings, "OPTIX_PROXY_BRIDGE_SECRET", "") or "").encode("utf-8")


def _denied(status: int = 403) -> JsonResponse:
    return JsonResponse({"allowed": False, "message": "Proxy bridge access denied."}, status=status)


def _verified(request: HttpRequest) -> bool:
    secret = _secret()
    if len(secret) < 32:
        return False
    try:
        timestamp = int(request.headers.get("X-OPTIX-Timestamp", "0"))
    except ValueError:
        return False
    if abs(int(time.time()) - timestamp) > MAX_SKEW_SECONDS:
        return False
    supplied = str(request.headers.get("X-OPTIX-Signature", "")).strip().lower()
    expected = hmac.new(secret, f"{timestamp}\n".encode("ascii") + request.body, hashlib.sha256).hexdigest()
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def _client(identity: object) -> ClientAccess | None:
    if not isinstance(identity, dict):
        return None
    office = str(identity.get("office_name") or "").strip()
    system = str(identity.get("system_number") or "").strip()
    device_id = str(identity.get("device_id") or "").strip()

    # Device ID is the durable cross-server identity. Dollar and Warrior may
    # use different display/system labels for the same PC, and those labels can
    # be edited independently. Requiring all three values caused an otherwise
    # approved PC to lose proxy access even though both servers had the same
    # stable Device ID.
    if device_id:
        matched = (
            ClientAccess.objects.filter(active=True, device_id=device_id)
            .select_related("config_bundle")
            .order_by("pk")
            .first()
        )
        if matched is not None:
            return matched
        # Never fall back to a mutable office/system label when the caller
        # supplied an unknown Device ID.
        return None

    if not office or not system:
        return None
    return ClientAccess.objects.filter(
        active=True,
        office_name__iexact=office,
        system_number=system,
    ).select_related("config_bundle").order_by("pk").first()


def _inner(method: str, path: str, body: dict, client: ClientAccess) -> HttpRequest:
    factory = RequestFactory()
    if method == "GET":
        request = factory.get(path)
    else:
        request = factory.post(path, data=json.dumps(body), content_type="application/json")
    request._optix_trusted_client = client
    request._optix_bridge_request = True
    return request


@csrf_exempt
@require_POST
def proxy_bridge(request: HttpRequest) -> JsonResponse:
    if not _verified(request):
        return _denied()
    try:
        payload = json.loads(request.body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
        action = str(payload.get("action") or "").strip().lower()
        client = _client(payload.get("client"))
        if client is None:
            return _denied()
        from . import views
        if action == "create":
            response = views.create_proxy_job(_inner("POST", "/api/v1/proxy-jobs/", payload.get("request") or {}, client))
        elif action == "status":
            job_id = int(payload.get("job_id"))
            response = views.proxy_job_detail(_inner("GET", f"/api/v1/proxy-jobs/{job_id}/", {}, client), job_id)
        elif action == "claim":
            response = views.proxy_exit_ip_claim(_inner("POST", "/api/v1/proxy-exit-claims/", payload.get("request") or {}, client))
        elif action == "cities":
            provider = str(payload.get("provider") or "")
            country = str(payload.get("country") or "")
            region = str(payload.get("region") or "")
            response = views.proxy_cities(_inner("GET", "/api/v1/proxy-cities/", {}, client), provider, country, region)
        elif action == "catalog":
            # Dollar uses its own activation/releases but consumes the same
            # provider geography as the Warrior-backed desktop. This private,
            # signed response keeps both applications in exact catalog parity.
            response = JsonResponse(
                {"allowed": True, "providers": views._catalog(flatten_p3_locations=False)}
            )
        else:
            return _denied(400)
        return JsonResponse(json.loads(response.content.decode("utf-8")), status=response.status_code)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return _denied(400)
