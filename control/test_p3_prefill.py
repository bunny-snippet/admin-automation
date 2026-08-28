from __future__ import annotations

import io
import json
from pathlib import Path

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from tools.build_p3_prefill_geo import DEFAULT_COUNTRIES as BUILDER_COUNTRIES

from .management.commands.prefill_p3_geo_pools import (
    DEFAULT_COUNTRIES as COMMAND_COUNTRIES,
)
from .models import ClientAccess, ConfigBundle


GEO_PATH = Path(__file__).resolve().parent / "data" / "p3_prefill_geo.json"
EXPECTED_COUNTRIES = (
    "DE",
    "ES",
    "CZ",
    "BE",
    "FR",
    "IT",
    "GB",
    "DK",
    "AU",
    "CA",
    "US",
)


class P3PrefillGeographyTests(SimpleTestCase):
    def test_builder_and_command_share_the_complete_default_country_set(self):
        self.assertEqual(BUILDER_COUNTRIES, EXPECTED_COUNTRIES)
        self.assertEqual(COMMAND_COUNTRIES, EXPECTED_COUNTRIES)

    def test_bundled_geography_contains_complete_au_ca_us_state_city_data(self):
        geography = json.loads(GEO_PATH.read_text(encoding="utf-8"))

        expected_counts = {
            "DK": (5, 3),
            "AU": (8, 154),
            "CA": (13, 605),
            "US": (57, 3119),
        }
        for country, (region_count, city_count) in expected_counts.items():
            with self.subTest(country=country):
                self.assertEqual(len(geography[country]["regions"]), region_count)
                self.assertEqual(len(geography[country]["cities"]), city_count)

        self.assertIn(
            {"code": "84", "name": "Hovedstaden"},
            geography["DK"]["regions"],
        )
        self.assertIn("Copenhagen", geography["DK"]["cities"])
        self.assertIn(
            {"code": "NSW", "name": "New South Wales"},
            geography["AU"]["regions"],
        )
        self.assertIn("Sydney", geography["AU"]["cities"])
        self.assertIn(
            {"code": "ON", "name": "Ontario"},
            geography["CA"]["regions"],
        )
        self.assertIn("Toronto", geography["CA"]["cities"])
        self.assertIn(
            {"code": "CA", "name": "California"},
            geography["US"]["regions"],
        )
        self.assertIn("Los Angeles", geography["US"]["cities"])


class P3PrefillCommandTests(TestCase):
    def test_status_only_uses_all_default_countries_and_locations(self):
        bundle = ConfigBundle(name="P3 test bundle", version=1)
        bundle.set_payload(
            {
                "P3_PROXY_USERNAME": "p3-user",
                "P3_API_KEY": "p3-key",
            }
        )
        bundle.save()
        ClientAccess.objects.create(
            name="P3 test device",
            ipv4="203.0.113.30",
            device_id="p3-test-device",
            office_name="P3 Office",
            system_number="1",
            config_bundle=bundle,
        )
        output = io.StringIO()

        call_command(
            "prefill_p3_geo_pools",
            office=["P3 Office"],
            status_only=True,
            stdout=output,
        )

        result = output.getvalue()
        self.assertIn("countries=11", result)
        self.assertIn("locations_per_bundle=5704", result)
        self.assertIn("COUNTRY targets=0/11", result)
        self.assertIn("STATE targets=0/742", result)
        self.assertIn("CITY targets=0/4951", result)
