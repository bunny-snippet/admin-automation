from __future__ import annotations

import re
import secrets
import urllib.parse

from celery import shared_task
from django.db import transaction

from .models import (
    ConfigBundle,
    ProxyCountryFile,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyPoolTarget,
)
from .proxy_jobs import fulfill_waiting_jobs, get_or_create_pool_target, proxy_fingerprint


DEFAULT_POOL_TARGET = 1000
DEFAULT_POOL_THRESHOLD = 200
SUPPORTED_DYNAMIC_PROVIDERS = frozenset({"P1", "P2", "P3"})


def _value(config: dict, *names: str) -> str:
    for name in names:
        value = str(config.get(name) or "").strip()
        if value:
            return value
    return ""


def _session() -> str:
    return secrets.token_hex(8)


def _protocol(config: dict, provider: str, default: str = "http") -> str:
    value = _value(config, f"{provider}_PROTOCOL").casefold()
    return value if value in {"http", "https", "socks5"} else default


def _proxy_url(protocol: str, host: str, port: int, username: str, password: str) -> str:
    user = urllib.parse.quote(username, safe="")
    secret = urllib.parse.quote(password, safe="")
    return f"{protocol}://{user}:{secret}@{host}:{int(port)}"


def provider_is_configured(provider: str, config: dict) -> bool:
    provider = provider.upper()
    if provider == "P1":
        return all((
            _value(config, "NIMBLE_ACCOUNT_NAME", "P1_ACCOUNT_NAME"),
            _value(config, "NIMBLE_PIPELINE_NAME", "P1_PIPELINE_NAME"),
            _value(config, "NIMBLE_PIPELINE_PASSWORD", "P1_PIPELINE_PASSWORD"),
        ))
    if provider == "P2":
        return all((
            _value(config, "INFATICA_API_USERNAME", "P2_API_USERNAME"),
            _value(config, "INFATICA_API_PASSWORD", "P2_API_PASSWORD"),
        ))
    if provider == "P3":
        return all((
            _value(config, "MASSIVE_PROXY_USERNAME", "P3_PROXY_USERNAME"),
            _value(config, "MASSIVE_API_KEY", "P3_API_KEY"),
        ))
    return False


def _generate(
    provider: str,
    country: str,
    region: str,
    city: str,
    count: int,
    config: dict,
) -> list[str]:
    provider = provider.upper()
    country = country.upper()
    result: list[str] = []
    if provider == "P1":
        account = _value(config, "NIMBLE_ACCOUNT_NAME", "P1_ACCOUNT_NAME")
        pipeline = _value(config, "NIMBLE_PIPELINE_NAME", "P1_PIPELINE_NAME")
        password = _value(config, "NIMBLE_PIPELINE_PASSWORD", "P1_PIPELINE_PASSWORD")
        if not all((account, pipeline, password)):
            raise ValueError("P1 credentials are unavailable")
        protocol = _protocol(config, provider)
        for _index in range(count):
            user = f"account-{account}-pipeline-{pipeline}-country-{country}"
            if region:
                user += f"-state-{region}"
            if city:
                user += f"-city-{re.sub(r'\s+', '_', city.lower())}"
            user += f"-session-{_session()}"
            result.append(_proxy_url(protocol, "ip.nimbleway.com", 7000, user, password))
    elif provider == "P2":
        username = _value(config, "INFATICA_API_USERNAME", "P2_API_USERNAME")
        password = _value(config, "INFATICA_API_PASSWORD", "P2_API_PASSWORD")
        if not all((username, password)):
            raise ValueError("P2 credentials are unavailable")
        protocol = _protocol(config, provider, "socks5")
        for index in range(count):
            port = 10000 + (index % 1000)
            user = f"{username}_c_{country}"
            if region:
                user += f"_sd_{region}"
            if city:
                user += "_city_" + re.sub(r"\s+", "-", city.strip())
            user += f"_s_{_session()}"
            result.append(_proxy_url(protocol, "pool.infatica.io", port, user, password))
    elif provider == "P3":
        username = _value(config, "MASSIVE_PROXY_USERNAME", "P3_PROXY_USERNAME")
        password = _value(config, "MASSIVE_API_KEY", "P3_API_KEY")
        if not all((username, password)):
            raise ValueError("P3 credentials are unavailable")
        protocol = _protocol(config, provider)
        for _index in range(count):
            user = f"{username}-country-{country}"
            if region:
                user += f"-subdivision-{region}"
            if city:
                user += f"-city-{re.sub(r'\s+', '-', city.strip())}"
            user += f"-session-{_session()}"
            result.append(
                _proxy_url(protocol, "network.joinmassive.com", 65534, user, password)
            )
    else:
        raise ValueError("Dynamic generation is not configured for this provider")
    return result


def ensure_pool_targets(
    *,
    target_count: int = DEFAULT_POOL_TARGET,
    replenish_below: int = DEFAULT_POOL_THRESHOLD,
) -> tuple[int, int]:
    """Create country-level pool targets before desktop users request them."""
    target_count = max(1, int(target_count))
    replenish_below = max(0, min(int(replenish_below), target_count - 1))
    countries = list(
        ProxyCountryFile.objects.filter(
            active=True,
            provider__active=True,
            provider__code__in=SUPPORTED_DYNAMIC_PROVIDERS,
        ).select_related("provider")
    )
    bundles = (
        ConfigBundle.objects.filter(active=True, clients__active=True)
        .distinct()
        .order_by("pk")
    )
    created = 0
    available_targets = 0
    for bundle in bundles:
        config = bundle.get_payload()
        for country in countries:
            provider_code = country.provider.code.upper()
            if not provider_is_configured(provider_code, config):
                continue
            _target, was_created = ProxyPoolTarget.objects.get_or_create(
                config_bundle=bundle,
                provider_code=provider_code,
                country_code=country.country_code.upper(),
                region="",
                city="",
                defaults={
                    "target_count": target_count,
                    "replenish_below": replenish_below,
                    "active": True,
                },
            )
            created += int(was_created)
            available_targets += 1
    return created, available_targets


def _mark_target_jobs_failed(target: ProxyPoolTarget, error: Exception) -> None:
    message = f"Proxy pool refill failed: {type(error).__name__}."[:1000]
    jobs = ProxyGenerationJob.objects.filter(
        client__config_bundle=target.config_bundle,
        provider_code=target.provider_code,
        country_code=target.country_code,
        region=target.region,
        city=target.city,
        status__in=("waiting_generation", "partial"),
    )
    jobs.filter(ready_count=0).update(status="failed", error=message)
    jobs.filter(ready_count__gt=0).update(status="partial", error=message)


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def refill_proxy_pool(self, target_id: int) -> int:
    """Fill one pool to its target and satisfy queued app jobs from that pool."""
    try:
        with transaction.atomic():
            target = (
                ProxyPoolTarget.objects.select_for_update()
                .select_related("config_bundle")
                .get(pk=target_id)
            )
            if not target.active:
                return 0
            available_before = target.entries.filter(state="available").count()
            needed = max(0, target.target_count - available_before)
            if needed:
                config = target.config_bundle.get_payload()
                if not provider_is_configured(target.provider_code, config):
                    raise ValueError(
                        f"{target.provider_code} credentials are unavailable"
                    )
                lines = _generate(
                    target.provider_code,
                    target.country_code,
                    target.region,
                    target.city,
                    needed,
                    config,
                )
                entries = []
                for line in lines:
                    entry = ProxyPoolEntry(
                        target=target,
                        proxy_fingerprint=proxy_fingerprint(line),
                    )
                    entry.set_proxy(line)
                    entries.append(entry)
                ProxyPoolEntry.objects.bulk_create(
                    entries,
                    batch_size=250,
                    ignore_conflicts=True,
                )
            available_after = target.entries.filter(state="available").count()
        fulfill_waiting_jobs(target)
        return max(0, available_after - available_before)
    except Exception as exc:
        try:
            target = ProxyPoolTarget.objects.select_related("config_bundle").get(
                pk=target_id
            )
            _mark_target_jobs_failed(target, exc)
        except ProxyPoolTarget.DoesNotExist:
            pass
        raise


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def generate_proxy_job(self, job_id: int) -> None:
    """Compatibility task: route old queued messages through the shared pool."""
    job = ProxyGenerationJob.objects.select_related("client__config_bundle").get(pk=job_id)
    if job.status not in {"waiting_generation", "partial"}:
        return
    target = get_or_create_pool_target(
        client=job.client,
        provider_code=job.provider_code,
        country_code=job.country_code,
        region=job.region,
        city=job.city,
    )
    refill_proxy_pool.run(target.pk)


@shared_task
def maintain_proxy_pools(force: bool = False) -> int:
    """Create missing country pools and refill low inventory in the background."""
    ensure_pool_targets()
    queued = 0
    targets = ProxyPoolTarget.objects.filter(active=True).select_related("config_bundle")
    for target in targets:
        config = target.config_bundle.get_payload()
        if not provider_is_configured(target.provider_code, config):
            continue
        available = target.entries.filter(state="available").count()
        if force or available <= target.replenish_below:
            refill_proxy_pool.delay(target.pk)
            queued += 1
    return queued
