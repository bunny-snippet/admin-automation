from django.test import TestCase

from .models import ClientAccess, ConfigBundle
from .optix_proxy_bridge import _client


class OptixProxyBridgeIdentityTests(TestCase):
    def setUp(self):
        self.bundle = ConfigBundle.objects.create(name="bridge-test")
        self.device = ClientAccess.objects.create(
            name="Abhay",
            ipv4="198.51.100.10",
            device_id="stable-device-id",
            office_name="Personal",
            system_number="Warrior system label",
            config_bundle=self.bundle,
        )

    def test_device_id_matches_when_dollar_system_label_differs(self):
        matched = _client({
            "office_name": "Personal",
            "system_number": "HP",
            "device_id": "stable-device-id",
        })

        self.assertEqual(matched, self.device)

    def test_unknown_device_id_does_not_fall_back_to_labels(self):
        matched = _client({
            "office_name": "Personal",
            "system_number": "Warrior system label",
            "device_id": "unknown-device-id",
        })

        self.assertIsNone(matched)
