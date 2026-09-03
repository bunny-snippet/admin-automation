from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import (
    ClientAccess,
    ConfigBundle,
    DesktopOfficeAccessPolicy,
    DesktopRuntimeConfiguration,
    DesktopSecurityConfiguration,
)


class FocusedOperationsPanelTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_superuser(
            username="panel-admin",
            email="panel@example.com",
            password="test-password",
        )
        self.client.force_login(user)
        self.bundle = ConfigBundle.objects.create(name="Panel bundle")
        self.access = ClientAccess.objects.create(
            name="Panel PC",
            ipv4="203.0.113.30",
            device_id="panel-device",
            office_name="Panel Office",
            system_number="1",
            config_bundle=self.bundle,
        )
        DesktopOfficeAccessPolicy.objects.create(
            office_name="Panel Office",
            allowed_provider_codes=["P3"],
            allowed_browser_codes=["B1"],
            allowed_device_codes=["desktop"],
        )
        DesktopRuntimeConfiguration.objects.update_or_create(
            channel="public",
            defaults={"ui_config": {"appName": "OPTIX"}},
        )
        DesktopSecurityConfiguration.objects.get_or_create(pk=1)

    def test_panel_navigation_contains_only_focused_operations(self):
        response = self.client.get(reverse("control:panel"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Proxy operations")
        self.assertContains(response, "OPTIX control")
        self.assertContains(response, "Office permissions")
        self.assertNotContains(response, "Suspicious activity")
        self.assertNotContains(response, "Domain activity")

    def test_new_optix_resources_are_available(self):
        for resource in (
            "office-access",
            "device-permissions",
            "desktop-releases",
            "desktop-components",
            "desktop-runtime",
            "desktop-security",
        ):
            with self.subTest(resource=resource):
                response = self.client.get(
                    reverse("control:panel-resource-api", args=(resource,))
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn("rows", response.json())

    def test_device_permission_resource_returns_resolved_policy(self):
        response = self.client.get(
            reverse("control:panel-resource-api", args=("device-permissions",))
        )
        row = response.json()["rows"][0]
        self.assertEqual(row["source"], "office")
        self.assertEqual(row["providers"], "P3")
        self.assertEqual(row["browsers"], "B1")
        self.assertEqual(row["devices"], "desktop")
