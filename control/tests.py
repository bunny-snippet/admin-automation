from __future__ import annotations

import json

from django.test import TestCase, override_settings
from django.urls import reverse

from .models import ClientAccess, ConfigBundle, Provider, ProxyCountryFile


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
)
class ControlApiTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="Office config", version=7)
        self.bundle.set_payload(
            {
                "APP_API_KEY": "browser-secret",
                "WARRIOR_API_KEY": "warrior-secret",
                "P1_PASSWORD": "proxy-secret",
            }
        )
        self.bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="Office system 1",
            ipv4="203.0.113.10",
            device_id="device-one",
            office_name="1115",
            system_number="1",
            config_bundle=self.bundle,
        )
        self.provider = Provider.objects.create(
            code="P1", display_name="P1", display_order=1
        )
        self.country = ProxyCountryFile(
            provider=self.provider,
            country_code="US",
            country_name="United States",
        )
        self.country.set_content("host:1000:user:pass\nhost:1001:user:pass\n")
        self.country.save()

    def bootstrap(
        self,
        reported="203.0.113.10",
        remote="203.0.113.10",
        device_id="device-one",
    ):
        return self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps(
                {
                    "reported_ipv4": reported,
                    "app_version": "1.6.1",
                    "device_id": device_id,
                }
            ),
            content_type="application/json",
            REMOTE_ADDR=remote,
        )

    def test_encrypted_fields_do_not_store_plaintext(self):
        self.assertNotIn("browser-secret", self.bundle.payload_ciphertext)
        self.assertNotIn("host:1000", self.country.content_ciphertext)
        self.assertEqual(self.bundle.get_payload()["APP_API_KEY"], "browser-secret")

    def test_public_ipv4_endpoint_returns_server_observed_ip(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True, "ipv4": "203.0.113.10"})
        self.assertIn("no-store", response["Cache-Control"])

    def test_non_whitelisted_ip_is_denied(self):
        response = self.bootstrap(reported="203.0.113.99", remote="203.0.113.99")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"allowed": False, "message": "Access denied."})

    def test_reported_ip_must_match_observed_ip(self):
        response = self.bootstrap(reported="203.0.113.11")
        self.assertEqual(response.status_code, 403)

    def test_unknown_device_on_allowed_ip_is_denied(self):
        response = self.bootstrap(device_id="not-authorized")
        self.assertEqual(response.status_code, 403)

    def test_allowed_bootstrap_merges_per_client_values(self):
        response = self.bootstrap()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["warrior_config"]["OFFICE_NAME"], "1115")
        self.assertEqual(payload["warrior_config"]["SYSTEM_NUMBER"], "1")
        self.assertEqual(payload["warrior_config"]["APP_API_KEY"], "browser-secret")
        self.assertEqual(payload["catalog"]["providers"][0]["id"], "P1")
        self.assertEqual(response["Cache-Control"], "no-store, no-cache, must-revalidate, private")

    def test_same_public_ip_can_have_multiple_authorized_systems(self):
        ClientAccess.objects.create(
            name="Office system 2",
            ipv4="203.0.113.10",
            device_id="device-two",
            office_name="1115",
            system_number="2",
            config_bundle=self.bundle,
        )
        response = self.bootstrap(device_id="device-two")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["warrior_config"]["SYSTEM_NUMBER"], "2")

    def test_ip_only_entry_accepts_blank_device_id(self):
        ClientAccess.objects.create(
            name="IP only office",
            ipv4="203.0.113.12",
            device_id="",
            office_name="shared",
            system_number="1",
            config_bundle=self.bundle,
        )
        response = self.bootstrap(
            reported="203.0.113.12",
            remote="203.0.113.12",
            device_id="",
        )
        self.assertEqual(response.status_code, 200)

    def test_proxy_content_requires_valid_ip_bound_bearer(self):
        token = self.bootstrap().json()["access_token"]
        response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["content"], "host:1000:user:pass\nhost:1001:user:pass\n")

        changed_ip = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.11",
        )
        self.assertEqual(changed_ip.status_code, 403)

        changed_device = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-two",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(changed_device.status_code, 403)

    def test_bad_token_is_denied(self):
        response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION="Bearer invalid",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_render_forwarded_first_ip_is_used(self):
        response = self.client.post(
            reverse("control:bootstrap"),
            data=json.dumps(
                {"reported_ipv4": "203.0.113.10", "device_id": "device-one"}
            ),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR="203.0.113.10, 10.0.0.2",
        )
        self.assertEqual(response.status_code, 200)

    def test_openapi_schema_and_swagger_docs(self):
        schema_response = self.client.get(reverse("control:openapi-schema"))
        self.assertEqual(schema_response.status_code, 200)
        self.assertEqual(schema_response.json()["openapi"], "3.1.0")
        self.assertIn("/api/v1/bootstrap/", schema_response.json()["paths"])

        docs_response = self.client.get(reverse("control:swagger-docs"))
        self.assertEqual(docs_response.status_code, 200)
        self.assertContains(docs_response, "SwaggerUIBundle")
