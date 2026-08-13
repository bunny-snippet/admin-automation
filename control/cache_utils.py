from __future__ import annotations

import hashlib

from django.core.cache import cache


ACCESS_AUDIT_VERSION_KEY = "panel:access-audit:version"
ACCESS_AUDIT_MIN_TTL = (11 * 60 + 5) * 60
ACCESS_AUDIT_MAX_TTL = (12 * 60 + 10) * 60


def access_audit_cache_version() -> int:
    """Return the shared audit snapshot version used by all web workers."""
    cache.add(ACCESS_AUDIT_VERSION_KEY, 1, timeout=None)
    try:
        return int(cache.get(ACCESS_AUDIT_VERSION_KEY) or 1)
    except (TypeError, ValueError):
        cache.set(ACCESS_AUDIT_VERSION_KEY, 1, timeout=None)
        return 1


def bump_access_audit_cache_version() -> int:
    """Invalidate audit page caches without scanning/deleting Redis keys."""
    if cache.add(ACCESS_AUDIT_VERSION_KEY, 2, timeout=None):
        return 2
    try:
        return int(cache.incr(ACCESS_AUDIT_VERSION_KEY))
    except (ValueError, TypeError):
        cache.set(ACCESS_AUDIT_VERSION_KEY, 2, timeout=None)
        return 2


def access_audit_cache_ttl(cache_key: str) -> int:
    """Spread old cache expiry between 11h05m and 12h10m."""
    spread = ACCESS_AUDIT_MAX_TTL - ACCESS_AUDIT_MIN_TTL
    digest = hashlib.sha256(cache_key.encode("utf-8")).digest()
    return ACCESS_AUDIT_MIN_TTL + int.from_bytes(digest[:4], "big") % (spread + 1)
