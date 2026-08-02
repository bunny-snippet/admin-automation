from __future__ import annotations

import secrets
import re

from celery import shared_task

from django.db import IntegrityError, transaction

from .models import ProxyGenerationJob, ProxyPoolEntry, ProxyPoolTarget
from .proxy_jobs import proxy_fingerprint, reserve_generated_proxy


def _value(config: dict, *names: str) -> str:
    for name in names:
        value = str(config.get(name) or "").strip()
        if value:
            return value
    return ""


def _session() -> str:
    return secrets.token_hex(8)


def _generate(provider: str, country: str, region: str, city: str, count: int, config: dict) -> list[str]:
    result: list[str] = []
    if provider == "P1":
        account = _value(config, "NIMBLE_ACCOUNT_NAME", "P1_ACCOUNT_NAME")
        pipeline = _value(config, "NIMBLE_PIPELINE_NAME", "P1_PIPELINE_NAME")
        password = _value(config, "NIMBLE_PIPELINE_PASSWORD", "P1_PIPELINE_PASSWORD")
        if not all((account, pipeline, password)):
            raise ValueError("P1 credentials are unavailable")
        for _ in range(count):
            user = f"account-{account}-pipeline-{pipeline}-country-{country}"
            if region: user += f"-state-{region}"
            if city: user += f"-city-{re.sub(r'\\s+', '_', city.lower())}"
            result.append(f"ip.nimbleway.com:7000:{user}-session-{_session()}:{password}")
    elif provider == "P2":
        username = _value(config, "INFATICA_API_USERNAME", "P2_API_USERNAME")
        password = _value(config, "INFATICA_API_PASSWORD", "P2_API_PASSWORD")
        if not all((username, password)):
            raise ValueError("P2 credentials are unavailable")
        for port in range(10000, 10000 + count):
            user = f"{username}_c_{country}"
            if region: user += f"_sd_{region}"
            if city: user += "_city_" + re.sub(r"\\s+", "-", city)
            result.append(f"pool.infatica.io:{port}:{user}_s_{_session()}:{password}")
    elif provider == "P3":
        username = _value(config, "MASSIVE_PROXY_USERNAME", "P3_PROXY_USERNAME")
        password = _value(config, "MASSIVE_API_KEY", "P3_API_KEY")
        if not all((username, password)):
            raise ValueError("P3 credentials are unavailable")
        for _ in range(count):
            user = f"{username}-country-{country}"
            if region: user += f"-subdivision-{region}"
            if city: user += f"-city-{city}"
            result.append(f"network.joinmassive.com:65534:{user}-session-{_session()}-sessionttl-60:{password}")
    else:
        raise ValueError("Dynamic generation is not configured for this provider")
    return result


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def generate_proxy_job(self, job_id: int) -> None:
    job = ProxyGenerationJob.objects.select_related("client__config_bundle").get(pk=job_id)
    if job.status not in {"waiting_generation", "partial"}:
        return
    config = job.client.config_bundle.get_payload()
    needed = max(0, job.requested_count - job.ready_count)
    try:
        lines = _generate(job.provider_code, job.country_code, job.region, job.city, needed, config)
        for line in lines:
            reserve_generated_proxy(client=job.client, job=job, provider_code=job.provider_code,
                                    country_code=job.country_code, region=job.region, city=job.city, value=line)
        job.refresh_from_db()
        job.ready_count = job.reservations.count()
        job.status = "ready" if job.ready_count == job.requested_count else "partial"
        job.save(update_fields=("ready_count", "status", "updated_at"))
    except Exception as exc:
        job.status = "failed" if not job.ready_count else "partial"
        job.error = str(exc)[:1000]
        job.save(update_fields=("status", "error", "updated_at"))


@shared_task(bind=True, autoretry_for=(), max_retries=0)
def refill_proxy_pool(self, target_id: int) -> int:
    """Pre-generate inventory so desktop requests receive ready sessions immediately."""
    target = ProxyPoolTarget.objects.select_related("config_bundle").get(pk=target_id)
    if not target.active:
        return 0
    available = target.entries.filter(state="available").count()
    needed = max(0, target.target_count - available)
    if not needed:
        return 0
    lines = _generate(target.provider_code, target.country_code, target.region, target.city, min(needed, 250), target.config_bundle.get_payload())
    created = 0
    for line in lines:
        try:
            with transaction.atomic():
                entry = ProxyPoolEntry(target=target, proxy_fingerprint=proxy_fingerprint(line))
                entry.set_proxy(line)
                entry.save(force_insert=True)
                created += 1
        except IntegrityError:
            continue
    return created


@shared_task
def maintain_proxy_pools() -> int:
    """Queue replenishment for each active pool at/below its low-water mark."""
    queued = 0
    for target in ProxyPoolTarget.objects.filter(active=True):
        if target.entries.filter(state="available").count() <= target.replenish_below:
            refill_proxy_pool.delay(target.pk)
            queued += 1
    return queued
