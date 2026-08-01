from __future__ import annotations

import io
import json
import zipfile

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .admin import import_catalog_zip
from .models import ClientAccess, ConfigBundle, Provider, ProxyCountryFile, ProxyReservation


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    TRUST_APP_REPORTED_IPV4=False,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
)
class ControlApiTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="Office config", version=7)
        self.bundle.set_payload(
            {
                "APP_API_KEY": "browser-secret",
                "TUBELIGHT_API_KEY": "tubelight-secret",
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

    def test_zip_catalog_import_replaces_existing_and_adds_new_country(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("P1/US__United States.txt", "new-host:1000:user:pass\n")
            archive.writestr("P1/AU__Australia.txt", "au-host:1000:user:pass\n")
        upload = SimpleUploadedFile("catalog.zip", buffer.getvalue(), content_type="application/zip")
        imported, replaced = import_catalog_zip(upload)
        self.assertEqual((imported, replaced), (2, 1))
        us = ProxyCountryFile.objects.get(provider__code="P1", country_code="US")
        au = ProxyCountryFile.objects.get(provider__code="P1", country_code="AU")
        self.assertEqual(us.get_content(), "new-host:1000:user:pass\n")
        self.assertEqual(au.country_name, "Australia")
        self.assertTrue(au.active)

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

    @override_settings(TRUST_APP_REPORTED_IPV4=True)
    def test_approved_app_reported_ip_drives_whitelist_and_proxy_token(self):
        response = self.bootstrap(
            reported="203.0.113.10",
            remote="100.64.0.19",
            device_id="device-one",
        )
        self.assertEqual(response.status_code, 200)
        token = response.json()["access_token"]
        proxy_response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.10",
            REMOTE_ADDR="100.64.0.21",
        )
        self.assertEqual(proxy_response.status_code, 200)

        changed_ip = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            HTTP_X_CLIENT_IPV4="203.0.113.11",
            REMOTE_ADDR="100.64.0.21",
        )
        self.assertEqual(changed_ip.status_code, 403)

    def test_unknown_device_on_allowed_ip_is_denied(self):
        response = self.bootstrap(device_id="not-authorized")
        self.assertEqual(response.status_code, 403)

    def test_allowed_bootstrap_merges_per_client_values(self):
        response = self.bootstrap()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["tubelight_config"]["OFFICE_NAME"], "1115")
        self.assertEqual(payload["tubelight_config"]["SYSTEM_NUMBER"], "1")
        self.assertEqual(payload["tubelight_config"]["APP_API_KEY"], "browser-secret")
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
        self.assertEqual(response.json()["tubelight_config"]["SYSTEM_NUMBER"], "2")

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

    def test_proxy_job_reserves_each_static_line_once_and_records_activity(self):
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "US", "count": 1}),
            content_type="application/json", **headers,
        )
        self.assertEqual(response.status_code, 201)
        job = response.json()["job"]
        self.assertEqual(job["status"], "ready")
        self.assertEqual(len(job["proxies"]), 1)
        self.assertNotIn("host:1000", ProxyReservation.objects.get(pk=job["proxies"][0]["reservation_id"]).proxy_ciphertext)

        second = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "US", "count": 2}),
            content_type="application/json", **headers,
        )
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.json()["job"]["ready_count"], 1)
        self.assertEqual(second.json()["job"]["status"], "partial")

        activity = self.client.post(
            reverse("control:profile-activity"),
            data=json.dumps({
                "job_id": job["id"], "reservation_id": job["proxies"][0]["reservation_id"],
                "status": "opened", "group_id": "8", "profile_name": "1115_sys_1_1",
                "profile_id": "profile-1", "start_urls": ["https://example.test/"],
            }),
            content_type="application/json", **headers,
        )
        self.assertEqual(activity.status_code, 201)

    def test_bad_token_is_denied(self):
        response = self.client.get(
            reverse("control:proxy-file", args=("P1", "US")),
            HTTP_AUTHORIZATION="Bearer invalid",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        CLOUDFLARE_ORIGIN_SECRET="test-origin-secret",
    )
    def test_verified_cloudflare_client_ip_has_priority(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="100.64.0.12",
            HTTP_X_TUBELIGHT_ORIGIN_SECRET="test-origin-secret",
            HTTP_CF_CONNECTING_IP="203.0.113.10",
            HTTP_X_REAL_IP="100.64.0.12",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ipv4"], "203.0.113.10")

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        CLOUDFLARE_ORIGIN_SECRET="test-origin-secret",
    )
    def test_spoofed_cloudflare_ip_without_origin_secret_is_rejected(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="100.64.0.12",
            HTTP_CF_CONNECTING_IP="203.0.113.10",
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(TRUST_PROXY_HEADERS=True)
    def test_railway_real_ip_is_used(self):
        response = self.client.get(
            reverse("control:public-ipv4"),
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_REAL_IP="203.0.113.10",
            HTTP_X_FORWARDED_FOR="10.0.0.3",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ipv4"], "203.0.113.10")

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
