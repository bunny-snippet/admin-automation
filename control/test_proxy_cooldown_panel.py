import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from .exit_ip_cooldown import cooldown_policy_payload


class ProxyCooldownPanelTests(TestCase):
    def setUp(self):
        self.url = reverse("control:panel-proxy-cooldown-api")
        self.admin = get_user_model().objects.create_superuser("policy-admin", "admin@example.test", "test")
        self.client.force_login(self.admin)

    def post(self, payload):
        return self.client.post(self.url, json.dumps(payload), content_type="application/json")

    def test_default_and_global_change(self):
        initial = self.client.get(self.url)
        self.assertEqual(initial.status_code, 200)
        self.assertIn("no-store", initial["Cache-Control"])
        self.assertTrue(initial.json()["policy"]["enabled"])
        self.assertTrue(initial.json()["can_change"])
        changed = self.post({"enabled": False, "expected_revision": initial.json()["policy"]["revision"]})
        self.assertEqual(changed.status_code, 200)
        self.assertFalse(changed.json()["policy"]["enabled"])
        stale = self.post({"enabled": True, "expected_revision": initial.json()["policy"]["revision"]})
        self.assertEqual(stale.status_code, 409)
        self.assertFalse(cooldown_policy_payload()["enabled"])

    def test_strict_inputs(self):
        for body in [[], {}, {"enabled": "false", "expected_revision": 0}, {"enabled": False}, {"enabled": False, "expected_revision": True}]:
            with self.subTest(body=body):
                self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.client.post(self.url, "{", content_type="application/json").status_code, 400)
        self.assertTrue(cooldown_policy_payload()["enabled"])

    def test_staff_read_only_anonymous_blocked_and_csrf(self):
        staff = get_user_model().objects.create_user("staff", password="test", is_staff=True)
        self.client.force_login(staff)
        self.assertFalse(self.client.get(self.url).json()["can_change"])
        self.assertEqual(self.post({"enabled": False, "expected_revision": 0}).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        self.assertEqual(csrf_client.post(self.url, json.dumps({"enabled": False, "expected_revision": 0}), content_type="application/json").status_code, 403)

    def test_panel_loads_control_assets(self):
        response = self.client.get(reverse("control:panel"))
        self.assertContains(response, "data-cooldown-url=")
        self.assertContains(response, "panel-cooldown.js")
        self.assertContains(response, "panel-cooldown.css")
