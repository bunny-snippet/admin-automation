import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import (
    BootstrapAudit,
    ClientAccess,
    ClientAccessIP,
    ConfigBundle,
    DesktopOfficeAccessPolicy,
    DesktopSecurityConfiguration,
    Provider,
    ProxyPoolEntry,
    ProxyPoolTarget,
)


class OperationsPanelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="ops-admin", email="ops@example.com", password="test-pass"
        )
        self.client.force_login(self.user)
        self.bundle = ConfigBundle.objects.create(name="IPLV-PC-01")
        self.bundle.set_payload({"MASSIVE_PROXY_USERNAME": "user", "MASSIVE_API_KEY": "secret"})
        self.bundle.save()
        self.device = ClientAccess.objects.create(
            name="IPLV system 01",
            ipv4="198.51.100.10",
            device_id="device-iplv-01",
            office_name="IPLV",
            system_number="01",
            config_bundle=self.bundle,
        )
        personal_bundle = ConfigBundle.objects.create(name="PERSONAL-TEST")
        ClientAccess.objects.create(
            name="Personal testing",
            ipv4="198.51.100.20",
            device_id="personal-device",
            office_name="Personal",
            system_number="01",
            config_bundle=personal_bundle,
        )
        Provider.objects.create(code="P3", display_name="P3", active=True)

    def post(self, name, body):
        return self.client.post(
            reverse(name),
            data=json.dumps(body),
            content_type="application/json",
        )

    def test_access_workspace_hides_personal_and_approves_existing_device(self):
        audit = BootstrapAudit.objects.create(
            observed_ip="203.0.113.44",
            reported_ip="203.0.113.44",
            device_id=self.device.device_id,
            allowed=False,
            reason="not-whitelisted",
            app_version="1.6.1",
        )
        response = self.client.get(reverse("control:panel-access-api"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["offices"], ["IPLV"])
        self.assertEqual(payload["unread_count"], 1)

        response = self.post("control:panel-access-api", {
            "action": "approve_request",
            "audit_id": audit.pk,
            "ipv4": "203.0.113.44",
            "scope": "device",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClientAccess.objects.filter(device_id=self.device.device_id).count(), 1)
        self.assertTrue(ClientAccessIP.objects.filter(client=self.device, ipv4="203.0.113.44", active=True).exists())
        audit.refresh_from_db()
        self.assertEqual(audit.review_status, BootstrapAudit.REVIEW_APPROVED)
        self.assertIsNotNone(audit.read_at)

    @patch("control.panel_operations.queue_refill_proxy_pool", return_value=True)
    def test_proxy_workspace_generates_and_removes_scoped_stock(self, queue_refill):
        response = self.post("control:panel-proxy-api", {
            "action": "generate",
            "scope": "device",
            "client_id": self.device.pk,
            "provider": "P3",
            "country": "US",
            "region": "CA",
            "target_count": 100,
            "threshold": 20,
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("P3 US / CA / Any city", response.json()["message"])
        self.assertIn("1 new location pool(s)", response.json()["message"])
        target = ProxyPoolTarget.objects.get(
            config_bundle=self.bundle,
            provider_code="P3",
            country_code="US",
            region="CA",
            city="",
        )
        entry = ProxyPoolEntry(target=target, proxy_fingerprint="f" * 64, state="available")
        entry.set_proxy("http://user:pass@example.com:8080")
        entry.save()

        response = self.post("control:panel-proxy-api", {
            "action": "remove_available",
            "scope": "device",
            "client_id": self.device.pk,
            "provider": "P3",
            "country": "US",
            "confirmation": "REMOVE AVAILABLE",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProxyPoolEntry.objects.filter(pk=entry.pk).exists())
        target.refresh_from_db()
        self.assertFalse(target.active)

    @patch("control.panel_operations.queue_refill_proxy_pool", return_value=True)
    def test_proxy_country_resize_updates_child_pools_and_trims_available(self, _queue):
        targets = [
            ProxyPoolTarget.objects.create(config_bundle=self.bundle, provider_code="P3", country_code="US", region="CA", city="Los Angeles", target_count=3, replenish_below=1),
            ProxyPoolTarget.objects.create(config_bundle=self.bundle, provider_code="P3", country_code="US", region="NY", city="New York", target_count=3, replenish_below=1),
        ]
        for target_index, target in enumerate(targets):
            for index in range(3):
                entry = ProxyPoolEntry(target=target, proxy_fingerprint=f"{target_index}{index}".ljust(64, "a"), state="available")
                entry.set_proxy(f"http://user:pass@host-{target_index}-{index}:8080")
                entry.save()
        response = self.post("control:panel-proxy-api", {
            "action": "resize", "scope": "device", "client_id": self.device.pk,
            "provider": "P3", "country": "US", "target_count": 2, "threshold": 1,
        })
        self.assertEqual(response.status_code, 200)
        for target in targets:
            target.refresh_from_db()
            self.assertEqual(target.target_count, 2)
            self.assertEqual(target.entries.filter(state="available").count(), 2)

    def test_optix_policy_override_and_remote_command_are_device_bound(self):
        response = self.post("control:panel-optix-api", {
            "action": "save_office",
            "office": "IPLV",
            "active": True,
            "providers": ["P3"],
            "browsers": ["B1"],
            "devices": ["desktop"],
            "show_logs": False,
            "release_channel": "testing",
            "activation_mode": "inherit",
        })
        self.assertEqual(response.status_code, 200)
        policy = DesktopOfficeAccessPolicy.objects.get(office_name="IPLV")
        self.assertEqual(policy.allowed_provider_codes, ["P3"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.release_channel, ClientAccess.RELEASE_CHANNEL_TESTING)

        response = self.post("control:panel-optix-api", {
            "action": "schedule_uninstall",
            "client_id": self.device.pk,
            "confirmation": "01",
        })
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.desktop_remote_action, ClientAccess.REMOTE_ACTION_UNINSTALL)
        self.assertEqual(self.device.desktop_remote_action_revision, 1)
        self.assertEqual(self.device.desktop_remote_action_requested_by, self.user)
        self.assertIsNone(self.device.desktop_remote_action_acknowledged_at)

    def test_optix_workspace_reports_legacy_usage_and_rotates_activation(self):
        self.device.desktop_client_product = ClientAccess.DESKTOP_PRODUCT_LEGACY
        self.device.desktop_client_version = "1.7.42"
        self.device.save(update_fields=("desktop_client_product", "desktop_client_version", "updated_at"))
        BootstrapAudit.objects.create(
            client=self.device,
            observed_ip=self.device.ipv4,
            reported_ip=self.device.ipv4,
            device_id=self.device.device_id,
            allowed=True,
            reason="allowed",
            app_version="1.7.42",
        )
        response = self.client.get(reverse("control:panel-optix-api"), {"office": "IPLV"})
        row = response.json()["rows"][0]
        self.assertEqual(row["product"]["label"], "I am the best")
        self.assertEqual(row["permission_source"], "Default policy")

        response = self.post("control:panel-optix-api", {
            "action": "rotate_activation_key",
            "required": True,
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["activation_key"].startswith("OPTIX-ACT-"))
        security = DesktopSecurityConfiguration.objects.get(pk=1)
        self.assertTrue(security.activation_required)

    def test_panel_navigation_has_focused_operations_and_releases(self):
        response = self.client.get(reverse("control:panel"))
        self.assertContains(response, 'data-route="access"')
        self.assertContains(response, 'data-route="proxy"')
        self.assertContains(response, 'data-route="optix"')
        self.assertContains(response, 'data-route="releases"')
        self.assertNotContains(response, 'data-route="overview"')
        self.assertNotContains(response, "Domain activity")
