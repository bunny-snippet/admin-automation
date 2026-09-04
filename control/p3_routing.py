from __future__ import annotations

from functools import lru_cache

import pycountry


@lru_cache(maxsize=4096)
def p3_subdivision_selector(country_code: str, region_code: str) -> str:
    """Build a resilient Massive subdivision selector.

    Massive accepts up to five comma-separated subdivision codes.  Some ISO
    catalogs expose a child subdivision (for example IE-MH / Meath) even when
    Massive currently has exits only at its parent subdivision (IE-L /
    Leinster).  Keep the requested code first, then add its ISO parents as
    availability fallbacks.  Countries with flat subdivisions are unchanged.
    """
    country = str(country_code or "").strip().upper()
    region = str(region_code or "").strip().upper()
    if not country or not region:
        return region

    result = [region]
    subdivision = pycountry.subdivisions.get(code=f"{country}-{region}")
    while subdivision is not None and len(result) < 5:
        parent_code = str(getattr(subdivision, "parent_code", "") or "").strip()
        if not parent_code or "-" not in parent_code:
            break
        parent_country, parent_region = parent_code.split("-", 1)
        parent_region = parent_region.strip().upper()
        if parent_country.upper() != country or not parent_region:
            break
        if parent_region not in result:
            result.append(parent_region)
        subdivision = pycountry.subdivisions.get(code=parent_code)
    return ",".join(result)
