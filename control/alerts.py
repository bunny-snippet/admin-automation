from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings

from .models import ProxyInventoryAlert


class SMSConfigurationError(RuntimeError):
    pass


def alert_message(alert: ProxyInventoryAlert) -> str:
    location = alert.country_code
    if alert.region:
        location += f"/{alert.region}"
    bundle = alert.config_bundle.name if alert.config_bundle_id else "unassigned"
    device = alert.system_number or (alert.device_id[:12] if alert.device_id else "unknown")
    return (
        "PROXY INVENTORY ALERT | "
        f"Office: {alert.office_name or '-'} | "
        f"Device: {device} | Bundle: {bundle} | "
        f"{alert.provider_code} {location} | "
        f"Ready: {alert.available_count}/{alert.requested_count}"
    )


def _recipients() -> list[str]:
    return [
        value.strip()
        for value in str(settings.PROXY_ALERT_SMS_TO or "").split(",")
        if value.strip()
    ]


def send_twilio_proxy_alert(alert: ProxyInventoryAlert) -> list[str]:
    """Send one normal SMS to every configured E.164 recipient."""
    account_sid = str(settings.TWILIO_ACCOUNT_SID or "").strip()
    auth_token = str(settings.TWILIO_AUTH_TOKEN or "").strip()
    from_number = str(settings.TWILIO_FROM_NUMBER or "").strip()
    messaging_service = str(settings.TWILIO_MESSAGING_SERVICE_SID or "").strip()
    recipients = _recipients()
    if not account_sid or not auth_token or not recipients:
        raise SMSConfigurationError(
            "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and PROXY_ALERT_SMS_TO are required."
        )
    if not from_number and not messaging_service:
        raise SMSConfigurationError(
            "Set TWILIO_FROM_NUMBER or TWILIO_MESSAGING_SERVICE_SID."
        )

    endpoint = (
        "https://api.twilio.com/2010-04-01/Accounts/"
        f"{urllib.parse.quote(account_sid, safe='')}/Messages.json"
    )
    authorization = base64.b64encode(
        f"{account_sid}:{auth_token}".encode("utf-8")
    ).decode("ascii")
    message_ids: list[str] = []
    body = alert_message(alert)

    for recipient in recipients:
        form = {"To": recipient, "Body": body}
        if messaging_service:
            form["MessagingServiceSid"] = messaging_service
        else:
            form["From"] = from_number
        request = urllib.request.Request(
            endpoint,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=settings.PROXY_ALERT_SMS_TIMEOUT_SECONDS,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Twilio HTTP {exc.code}: {detail}") from exc
        message_ids.append(str(payload.get("sid") or ""))
    return message_ids
