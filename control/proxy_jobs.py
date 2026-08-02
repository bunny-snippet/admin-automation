from __future__ import annotations

import hashlib
from collections.abc import Iterable

from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import (ClientAccess, ProxyCountryFile, ProxyGenerationJob, ProxyPoolEntry, ProxyPoolTarget, ProxyReservation)


def proxy_fingerprint(value: str) -> str:
    """Stable, secret-free identifier for a proxy line."""
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def usable_lines(content: str) -> Iterable[str]:
    for raw in content.splitlines():
        value = raw.strip()
        if value and not value.startswith("#"):
            yield value


@transaction.atomic
def reserve_static_proxies(*, client: ClientAccess, job: ProxyGenerationJob,
                           provider_code: str, country_code: str,
                           region: str = "", city: str = "") -> list[ProxyReservation]:
    """Reserve never-before-issued lines from a country's encrypted catalog."""
    source = (ProxyCountryFile.objects.select_related("provider").select_for_update()
              .filter(provider__code=provider_code, provider__active=True,
                      country_code=country_code, active=True).first())
    if source is None:
        return []
    reservations: list[ProxyReservation] = []
    for value in usable_lines(source.get_content()):
        if len(reservations) >= job.requested_count:
            break
        try:
            # A savepoint keeps the surrounding allocation transaction usable
            # when another worker wins the unique-fingerprint race.
            with transaction.atomic():
                reservation = ProxyReservation(
                    client=client, job=job, provider_code=provider_code,
                    country_code=country_code, region=region, city=city,
                    proxy_fingerprint=proxy_fingerprint(value),
                )
                reservation.set_proxy(value)
                reservation.save(force_insert=True)
        except IntegrityError:
            continue
        reservations.append(reservation)
    return reservations


def reserve_generated_proxy(*, client: ClientAccess, job: ProxyGenerationJob,
                            provider_code: str, country_code: str, value: str,
                            region: str = "", city: str = "") -> ProxyReservation | None:
    try:
        with transaction.atomic():
            reservation = ProxyReservation(
                client=client, job=job, provider_code=provider_code,
                country_code=country_code, region=region, city=city,
                proxy_fingerprint=proxy_fingerprint(value),
            )
            reservation.set_proxy(value)
            reservation.save(force_insert=True)
            return reservation
    except IntegrityError:
        return None


@transaction.atomic
def reserve_pool_proxies(*, client: ClientAccess, job: ProxyGenerationJob, provider_code: str, country_code: str, region: str = "", city: str = "") -> list[ProxyReservation]:
    """Atomically issue unused, pre-generated pool entries exactly once."""
    entries = (ProxyPoolEntry.objects.select_for_update().filter(
        target__config_bundle=client.config_bundle, target__provider_code=provider_code,
        target__country_code=country_code, target__region=region, target__city=city,
        target__active=True, state="available").order_by("created_at")[:job.requested_count])
    now = timezone.now()
    issued = []
    for entry in entries:
        value = entry.get_proxy()
        entry.state, entry.reserved_client, entry.reserved_at = "reserved", client, now
        entry.save(update_fields=("state", "reserved_client", "reserved_at"))
        reservation = ProxyReservation(client=client, job=job, pool_entry=entry, provider_code=provider_code, country_code=country_code, region=region, city=city, proxy_fingerprint=entry.proxy_fingerprint)
        reservation.set_proxy(value)
        reservation.save(force_insert=True)
        issued.append(reservation)
    return issued


def get_or_create_pool_target(*, client: ClientAccess, provider_code: str, country_code: str, region: str = "", city: str = "") -> ProxyPoolTarget:
    return ProxyPoolTarget.objects.get_or_create(config_bundle=client.config_bundle, provider_code=provider_code, country_code=country_code, region=region, city=city)[0]
