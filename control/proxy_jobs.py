from __future__ import annotations

import hashlib
from collections.abc import Iterable

from django.db import IntegrityError, transaction

from .models import ClientAccess, ProxyCountryFile, ProxyGenerationJob, ProxyReservation


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
