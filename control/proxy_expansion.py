from __future__ import annotations

from dataclasses import dataclass

from .models import ProxyCityCatalog, ProxyRegionCatalog
from .p3_geo_catalog import P3_GEO_ACCOUNT_KEY


EXPANDED_CITY_TARGET = 40
EXPANDED_CITY_THRESHOLD = 8


@dataclass(frozen=True)
class ProxyLocationSpec:
    region: str
    city: str
    level: str


def _city_catalog_provider(provider_code: str) -> str:
    # P1 and P3 both accept GeoNames-compatible English city names.  P3 owns
    # the shared server catalog so that we do not duplicate tens of thousands
    # of identical rows for P1.
    return "P3" if provider_code in {"P1", "P3"} else provider_code


def proxy_location_specs(
    provider_code: str,
    country_code: str,
    region_code: str = "",
    city_name: str = "",
) -> list[ProxyLocationSpec]:
    """Expand the panel's Any selections into concrete pool locations."""
    provider = str(provider_code or "").strip().upper()
    country = str(country_code or "").strip().upper()
    region = str(region_code or "").strip()
    city = str(city_name or "").strip()
    if not provider or not country:
        return []
    if provider not in {"P1", "P3"}:
        return [ProxyLocationSpec(region=region, city=city, level="exact")]

    region_rows = list(
        ProxyRegionCatalog.objects.filter(
            provider__code=provider,
            provider__active=True,
            country_code=country,
            active=True,
        )
        .order_by("region_name", "region_code")
        .values_list("region_code", flat=True)
        .distinct()
    )
    if region and region not in region_rows:
        return []

    city_provider = _city_catalog_provider(provider)
    city_query = ProxyCityCatalog.objects.filter(
        provider__code=city_provider,
        provider__active=True,
        account_key=P3_GEO_ACCOUNT_KEY,
        country_code=country,
        active=True,
    )
    if city:
        canonical = str(
            city_query.filter(city_name__iexact=city)
            .order_by("city_name")
            .values_list("city_name", flat=True)
            .first()
            or ""
        )
        return (
            [ProxyLocationSpec(region="", city=canonical, level="city")]
            if canonical
            else []
        )

    if region:
        specs = [ProxyLocationSpec(region=region, city="", level="region")]
        # Region-specific rows are used when a provider geography sync has
        # supplied that relationship. Country-scoped rows are deliberately
        # not guessed into an unrelated state.
        regional_cities = city_query.filter(region_code=region)
        specs.extend(
            ProxyLocationSpec(region="", city=name, level="city")
            for name in regional_cities.order_by("city_name")
            .values_list("city_name", flat=True)
            .distinct()
        )
        return specs

    specs = [ProxyLocationSpec(region="", city="", level="country")]
    specs.extend(
        ProxyLocationSpec(region=code, city="", level="region")
        for code in region_rows
    )
    specs.extend(
        ProxyLocationSpec(region="", city=name, level="city")
        for name in city_query.order_by("city_name")
        .values_list("city_name", flat=True)
        .distinct()
    )
    return specs


def location_stock_settings(
    spec: ProxyLocationSpec,
    target_count: int,
    replenish_below: int,
) -> tuple[int, int]:
    if spec.level != "city":
        return target_count, replenish_below
    city_target = min(target_count, EXPANDED_CITY_TARGET)
    city_threshold = min(replenish_below, EXPANDED_CITY_THRESHOLD, city_target)
    return city_target, max(1, city_threshold)
