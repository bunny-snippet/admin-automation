from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .admin import import_catalog_zip
from .models import (
    ClientAccess, ConfigBundle, ExtensionPackage, ProfileDomainActivity,
    Provider, ProxyCountryFile, ProxyGenerationJob, ProxyPoolTarget,
    ProxyReservation,
)
from .proxy_jobs import reserve_pool_proxies
from .tasks import (
    _generate, ensure_pool_targets, queue_refill_proxy_pool, refill_proxy_pool,
)


@override_settings(
    TRUST_PROXY_HEADERS=False,
    REQUIRE_REPORTED_IP_MATCH=True,
    TRUST_APP_REPORTED_IPV4=False,
    BOOTSTRAP_RATE_LIMIT_PER_MINUTE=100,
    BOOTSTRAP_TOKEN_MAX_AGE=300,
)
class ControlApiTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(
            name="Office config",
            version=7,
            browser_group_id="2255",
            browser_group_name="Testing",
        )
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
            profile_name="Device Alpha",
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
        self.assertEqual(payload["tubelight_config"]["BROWSER_GROUP_ID"], "2255")
        self.assertEqual(payload["tubelight_config"]["BROWSER_GROUP_NAME"], "Testing")
        self.assertEqual(payload["tubelight_config"]["DEVICE_PROFILE_NAME"], "Device Alpha")
        self.assertEqual(
            payload["assignment"],
            {
                "browser_group_id": "2255",
                "browser_group_name": "Testing",
                "profile_name": "Device Alpha",
            },
        )
        self.assertEqual(payload["catalog"]["providers"][0]["id"], "P1")
        self.assertEqual(response["Cache-Control"], "no-store, no-cache, must-revalidate, private")

    def test_bootstrap_delivers_active_extension_and_authenticated_zip(self):
        package = ExtensionPackage(
            name="Audit extension",
            filename="audit-extension.zip",
            version=3,
            active=True,
            status=True,
            is_top=True,
        )
        package.set_package(b"PK\x03\x04test-extension")
        package.save()

        bootstrap = self.bootstrap().json()
        row = bootstrap["catalog"]["extensions"][0]
        self.assertEqual(row["id"], package.pk)
        self.assertTrue(row["status"])
        self.assertTrue(row["is_top"])
        response = self.client.get(
            reverse("control:extension-package", args=(package.pk,)),
            HTTP_AUTHORIZATION=f"Bearer {bootstrap['access_token']}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"PK\x03\x04test-extension")

    def test_bootstrap_delivers_every_packaged_extension_and_status(self):
        first = ExtensionPackage(
            name="First extension",
            filename="first.zip",
            active=False,
            status=True,
        )
        first.set_package(b"PK\x03\x04first")
        first.save()
        second = ExtensionPackage(
            name="Second extension",
            filename="second.zip",
            active=True,
            status=False,
        )
        second.set_package(b"PK\x03\x04second")
        second.save()
        ExtensionPackage.objects.create(
            name="Missing package",
            filename="missing.zip",
            active=True,
            status=True,
        )

        bootstrap = self.bootstrap().json()
        rows = {
            row["id"]: row
            for row in bootstrap["catalog"]["extensions"]
        }
        self.assertEqual(set(rows), {first.pk, second.pk})
        self.assertTrue(rows[first.pk]["status"])
        self.assertFalse(rows[second.pk]["status"])

        response = self.client.get(
            reverse("control:extension-package", args=(first.pk,)),
            HTTP_AUTHORIZATION=f"Bearer {bootstrap['access_token']}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"PK\x03\x04first")

    def test_same_public_ip_can_have_multiple_authorized_systems(self):
        ClientAccess.objects.create(
            name="Office system 2",
            ipv4="203.0.113.10",
            device_id="device-two",
            office_name="1115",
            system_number="2",
            profile_name="Device Beta",
            config_bundle=self.bundle,
        )
        response = self.bootstrap(device_id="device-two")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["tubelight_config"]["SYSTEM_NUMBER"], "2")
        self.assertEqual(
            response.json()["tubelight_config"]["DEVICE_PROFILE_NAME"],
            "Device Beta",
        )

    def test_assignment_defaults_to_testing_and_client_name(self):
        self.bundle.browser_group_id = ""
        self.bundle.browser_group_name = ""
        self.bundle.save(update_fields=("browser_group_id", "browser_group_name"))
        self.client_access.profile_name = ""
        self.client_access.save(update_fields=("profile_name",))

        response = self.bootstrap()

        self.assertEqual(response.status_code, 200)
        config = response.json()["tubelight_config"]
        self.assertEqual(config["BROWSER_GROUP_ID"], "")
        self.assertEqual(config["BROWSER_GROUP_NAME"], "Testing")
        self.assertEqual(config["DEVICE_PROFILE_NAME"], "Office system 1")

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

    def test_proxy_job_returns_per_line_socks5_protocol(self):
        country = ProxyCountryFile(
            provider=self.provider,
            country_code="CA",
            country_name="Canada",
        )
        country.set_content("socks5://user:pass@proxy.example:1080\n")
        country.save()
        token = self.bootstrap().json()["access_token"]
        response = self.client.post(
            reverse("control:proxy-job-create"),
            data=json.dumps({"provider": "P1", "country": "CA", "count": 1}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_DEVICE_ID="device-one",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(response.status_code, 201)
        proxy = response.json()["job"]["proxies"][0]
        self.assertEqual(proxy["protocol"], "socks5")
        self.assertEqual(proxy["proxy"], "socks5://user:pass@proxy.example:1080")

    def test_profile_domain_batch_is_sanitized_idempotent_and_filterable(self):
        token = self.bootstrap().json()["access_token"]
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {token}",
            "HTTP_X_DEVICE_ID": "device-one",
            "REMOTE_ADDR": "203.0.113.10",
        }
        payload = {
            "session_id": "session-123",
            "group_id": "2255",
            "profile_name": "1115_sys_1_1",
            "profile_id": "profile-1",
            "browser_id": "1217093",
            "session_started_at": "2026-08-02T13:00:00Z",
            "session_ended_at": "2026-08-02T13:20:00Z",
            "domains": [
                {
                    "domain": "www.Example.Domain.com",
                    "first_visited_at": "2026-08-02T13:01:00Z",
                    "last_visited_at": "2026-08-02T13:02:00Z",
                    "visit_count": 2,
                },
                {
                    "domain": "ipapi.co",
                    "first_visited_at": "2026-08-02T13:00:10Z",
                    "last_visited_at": "2026-08-02T13:00:10Z",
                    "visit_count": 1,
                },
            ],
        }
        response = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["accepted"], 2)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)
        row = ProfileDomainActivity.objects.get(domain="www.example.domain.com")
        self.assertEqual(row.profile_id, "profile-1")
        self.assertEqual(row.visit_count, 2)

        repeated = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(repeated.status_code, 201)
        self.assertEqual(repeated.json()["updated"], 2)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)

        payload["domains"] = [{
            "domain": "https://example.com/private?token=secret",
            "first_visited_at": "2026-08-02T13:01:00Z",
            "last_visited_at": "2026-08-02T13:01:00Z",
            "visit_count": 1,
        }]
        rejected = self.client.post(
            reverse("control:profile-domains"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(ProfileDomainActivity.objects.count(), 2)

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


class ProxyPoolTaskTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle(name="Pool config", version=1)
        self.bundle.set_payload(
            {
                "P2_API_USERNAME": "proxy-user",
                "P2_API_PASSWORD": "proxy-password",
                "P2_PROTOCOL": "socks5",
            }
        )
        self.bundle.save()
        self.client_access = ClientAccess.objects.create(
            name="Pool device",
            ipv4="203.0.113.70",
            device_id="pool-device",
            office_name="Pool office",
            system_number="1",
            config_bundle=self.bundle,
        )
        self.provider = Provider.objects.create(
            code="P2", display_name="P2", display_order=2
        )
        self.country = ProxyCountryFile(
            provider=self.provider,
            country_code="US",
            country_name="United States",
        )
        self.country.set_content("")
        self.country.save()

    def test_configured_country_targets_are_created_before_app_requests(self):
        created, configured = ensure_pool_targets(target_count=5, replenish_below=2)

        self.assertGreaterEqual(created, 249)
        self.assertEqual(configured, created)
        self.assertEqual(
            ProxyCountryFile.objects.filter(provider__code="P2").count(),
            249,
        )
        target = ProxyPoolTarget.objects.get(provider_code="P2", country_code="US")
        self.assertEqual(target.provider_code, "P2")
        self.assertEqual(target.country_code, "US")
        self.assertEqual(target.target_count, 5)
        self.assertEqual(target.replenish_below, 2)

    def test_p1_vps_environment_credentials_create_global_and_state_targets(self):
        with mock.patch.dict(
            "os.environ",
            {
                "NIMBLE_ACCOUNT_NAME": "account",
                "NIMBLE_PIPELINE_NAME": "pipeline",
                "NIMBLE_PIPELINE_PASSWORD": "password",
            },
            clear=False,
        ):
            ensure_pool_targets(target_count=5, replenish_below=2)

        self.assertEqual(
            ProxyPoolTarget.objects.filter(provider_code="P1", region="").count(),
            249,
        )
        self.assertTrue(
            ProxyPoolTarget.objects.filter(
                provider_code="P1", country_code="US", region="CA"
            ).exists()
        )
        self.assertFalse(
            ProxyPoolTarget.objects.filter(provider_code="P3", region__gt="").exists()
        )

    def test_p2_generation_uses_country_session_and_explicit_protocol(self):
        lines = _generate(
            "P2",
            "US",
            "",
            "",
            2,
            self.bundle.get_payload(),
        )

        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("socks5://"))
        self.assertIn("_c_US_s_", lines[0])
        self.assertTrue(lines[0].endswith("@pool.infatica.io:10000"))
        self.assertTrue(lines[1].endswith("@pool.infatica.io:10001"))

    def test_refill_fills_target_and_progressively_completes_waiting_job(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            target_count=5,
            replenish_below=2,
        )
        job = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P2",
            country_code="US",
            requested_count=3,
            status="waiting_generation",
        )

        created = refill_proxy_pool.run(target.pk)

        job.refresh_from_db()
        self.assertEqual(created, 5)
        self.assertEqual(job.status, "ready")
        self.assertEqual(job.ready_count, 3)
        self.assertEqual(job.reservations.count(), 3)
        self.assertEqual(target.entries.filter(state="available").count(), 2)

        second = ProxyGenerationJob.objects.create(
            client=self.client_access,
            provider_code="P2",
            country_code="US",
            requested_count=2,
            status="queued",
        )
        issued = reserve_pool_proxies(
            client=self.client_access,
            job=second,
            provider_code="P2",
            country_code="US",
        )
        self.assertEqual(len(issued), 2)
        self.assertEqual(target.entries.filter(state="available").count(), 0)

        self.assertEqual(refill_proxy_pool.run(target.pk), 5)
        self.assertEqual(target.entries.filter(state="available").count(), 5)

    def test_only_one_outstanding_refill_is_queued_per_target(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
            target_count=5,
            replenish_below=2,
        )

        with mock.patch("control.tasks.refill_proxy_pool.delay") as delay:
            self.assertTrue(queue_refill_proxy_pool(target.pk))
            self.assertFalse(queue_refill_proxy_pool(target.pk))

        delay.assert_called_once_with(target.pk)
        target.refresh_from_db()
        self.assertTrue(target.refill_pending)

        self.assertEqual(refill_proxy_pool.run(target.pk), 5)
        target.refresh_from_db()
        self.assertFalse(target.refill_pending)

    def test_refill_claim_is_released_when_enqueue_fails(self):
        target = ProxyPoolTarget.objects.create(
            config_bundle=self.bundle,
            provider_code="P2",
            country_code="US",
        )
        with mock.patch(
            "control.tasks.refill_proxy_pool.delay",
            side_effect=RuntimeError("broker"),
        ):
            with self.assertRaises(RuntimeError):
                queue_refill_proxy_pool(target.pk)
        target.refresh_from_db()
        self.assertFalse(target.refill_pending)


class StaffPanelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="panel-admin",
            email="panel@example.com",
            password="StrongPanelPassword123!",
        )
        self.bundle = ConfigBundle.objects.create(
            name="Panel config",
            browser_group_id="701",
            browser_group_name="Testing",
        )
        self.client_access = ClientAccess.objects.create(
            name="North device 1",
            ipv4="203.0.113.40",
            device_id="device-panel-one",
            office_name="North",
            system_number="1",
            profile_name="North One",
            config_bundle=self.bundle,
            last_seen_at=timezone.now(),
        )
        now = timezone.now()
        self.activity = ProfileDomainActivity.objects.create(
            client=self.client_access,
            session_id="session-panel-1",
            group_id="701",
            profile_name="North One",
            profile_id="profile-panel-1",
            browser_id="991",
            domain="www.example.com",
            first_visited_at=now - timedelta(minutes=12),
            last_visited_at=now - timedelta(minutes=2),
            visit_count=3,
            session_started_at=now - timedelta(minutes=15),
            session_ended_at=now,
        )
        ProfileDomainActivity.objects.create(
            client=self.client_access,
            session_id="session-panel-1",
            group_id="701",
            profile_name="North One",
            profile_id="profile-panel-1",
            browser_id="991",
            domain="docs.example.com",
            first_visited_at=now - timedelta(minutes=8),
            last_visited_at=now - timedelta(minutes=4),
            visit_count=2,
            session_started_at=now - timedelta(minutes=15),
            session_ended_at=now,
        )

    def login(self):
        self.client.force_login(self.user)

    def test_panel_uses_existing_admin_authentication(self):
        response = self.client.get(reverse("control:panel"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("admin:login"), response["Location"])

        self.login()
        response = self.client.get(reverse("control:panel"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Automation Control Center")
        self.assertContains(response, "Domain activity")

    def test_overview_and_every_sidebar_resource_are_api_backed(self):
        self.login()
        overview = self.client.get(reverse("control:panel-overview-api"))
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["cards"]["active_devices"], 1)
        self.assertEqual(overview.json()["cards"]["domain_visits_24h"], 5)

        resources = (
            "devices", "configurations", "groups", "providers",
            "proxy-catalog", "extensions", "proxy-pools", "proxy-inventory",
            "proxy-jobs", "reservations", "profile-activity", "access-audit",
        )
        for resource in resources:
            with self.subTest(resource=resource):
                response = self.client.get(
                    reverse("control:panel-resource-api", args=(resource,))
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn("rows", response.json())
                self.assertIn("columns", response.json())

    def test_domain_activity_filters_detail_and_csv_are_precise(self):
        self.login()
        response = self.client.get(
            reverse("control:panel-domain-activity-api"),
            {"range": "30d", "office": "North", "domain": "www.example"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["metrics"]["visits"], 3)
        self.assertEqual(payload["metrics"]["unique_domains"], 1)
        self.assertEqual(payload["rows"][0]["device_id"], "device-panel-one")
        self.assertEqual(payload["rows"][0]["profile_id"], "profile-panel-1")
        self.assertEqual(payload["rows"][0]["group_id"], "701")

        detail = self.client.get(
            reverse("control:panel-domain-activity-detail-api", args=(self.activity.pk,))
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(len(detail.json()["session_domains"]), 2)
        self.assertEqual(detail.json()["activity"]["ipv4"], "203.0.113.40")

        export = self.client.get(
            reverse("control:panel-domain-activity-export"),
            {"range": "30d", "office": "North"},
        )
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export["Content-Type"], "text/csv; charset=utf-8")
        exported = export.content.decode("utf-8")
        self.assertIn("www.example.com", exported)
        self.assertIn("device-panel-one", exported)
