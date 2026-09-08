import hashlib
import hmac
import json
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from .optix_proxy_bridge import proxy_bridge


TEST_SECRET = "isolated-cooldown-bridge-test-secret-0001"
POLICY = {"enabled": True, "cooldown_hours": 25, "updated_at": None, "revision": 0}


def signed_request(values, *, action="cooldown-policy", timestamp=2000000000):
    raw = json.dumps({"action": action, "request": values}, separators=(",", ":")).encode()
    signature = hmac.new(TEST_SECRET.encode(), str(timestamp).encode() + b"\n" + raw, hashlib.sha256).hexdigest()
    return RequestFactory().post(
        "/bridge/", data=raw, content_type="application/json",
        HTTP_X_OPTIX_TIMESTAMP=str(timestamp), HTTP_X_OPTIX_SIGNATURE=signature,
    )


@override_settings(OPTIX_PROXY_BRIDGE_SECRET=TEST_SECRET)
@patch("control.optix_proxy_bridge.time.time", return_value=2000000000)
class CooldownBridgeSecurityTests(SimpleTestCase):
    @patch("control.exit_ip_cooldown.cooldown_policy_payload", return_value=POLICY)
    @patch("control.optix_proxy_bridge._client")
    def test_read_requires_no_desktop_lookup(self, client, policy, _clock):
        response = proxy_bridge(signed_request({"operation": "get", "actor": "dollar:staff"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"ok": True, "policy": POLICY})
        client.assert_not_called()
        policy.assert_called_once_with()

    @patch("control.exit_ip_cooldown.set_cooldown_policy", return_value={**POLICY, "enabled": False, "revision": 1})
    @patch("control.optix_proxy_bridge._client")
    def test_write_passes_strict_values_and_actor(self, client, setter, _clock):
        response = proxy_bridge(signed_request({"operation": "set", "enabled": False, "expected_revision": 0, "actor": "dollar:admin"}))
        self.assertEqual(response.status_code, 200)
        setter.assert_called_once_with(False, actor="dollar:admin", expected_revision=0)
        client.assert_not_called()

    @patch("control.exit_ip_cooldown.set_cooldown_policy")
    def test_unsigned_tampered_expired_and_desktop_credentials_cannot_write(self, setter, _clock):
        values = {"operation": "set", "enabled": False, "expected_revision": 0, "actor": "attacker"}
        unsigned = RequestFactory().post("/bridge/", data=json.dumps({"action": "cooldown-policy", "request": values}), content_type="application/json", HTTP_X_API_KEY="desktop-only-token")
        tampered = signed_request(values)
        tampered.META["HTTP_X_OPTIX_SIGNATURE"] = "0" * 64
        malformed = signed_request(values)
        malformed.META["HTTP_X_OPTIX_SIGNATURE"] = "\u00e9" * 64
        stale = signed_request(values, timestamp=1999999800)
        for request in (unsigned, tampered, malformed, stale):
            with self.subTest(request=request):
                self.assertEqual(proxy_bridge(request).status_code, 403)
        setter.assert_not_called()

    @patch("control.exit_ip_cooldown.set_cooldown_policy")
    def test_malformed_signed_writes_are_rejected(self, setter, _clock):
        good = {"operation": "set", "enabled": False, "expected_revision": 0, "actor": "admin"}
        invalid = [None, [], {}, {**good, "enabled": "false"}, {**good, "enabled": 0},
                   {**good, "expected_revision": True}, {**good, "expected_revision": "0"},
                   {**good, "expected_revision": -1}, {**good, "actor": None},
                   {**good, "actor": "admin\nforged"}, {**good, "operation": "SET"},
                   {**good, "extra": "unexpected"}, {key: value for key, value in good.items() if key != "expected_revision"},
                   {"operation": "get", "actor": "admin", "enabled": False}]
        for values in invalid:
            with self.subTest(values=values):
                self.assertEqual(proxy_bridge(signed_request(values)).status_code, 400)
        setter.assert_not_called()

    @patch("control.exit_ip_cooldown.set_cooldown_policy", side_effect=ValueError("private conflict detail"))
    def test_stale_write_is_conflict_without_internal_detail(self, setter, _clock):
        response = proxy_bridge(signed_request({"operation": "set", "enabled": False, "expected_revision": 0, "actor": "admin"}))
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(b"private conflict detail", response.content)

    @patch("control.exit_ip_cooldown.set_cooldown_policy")
    @patch("control.optix_proxy_bridge._client", return_value=None)
    def test_policy_values_inside_normal_claim_do_not_dispatch_write(self, client, setter, _clock):
        response = proxy_bridge(signed_request({"operation": "set", "enabled": False, "expected_revision": 0, "actor": "admin"}, action="claim"))
        self.assertEqual(response.status_code, 403)
        client.assert_called_once()
        setter.assert_not_called()


@override_settings(OPTIX_PROXY_BRIDGE_SECRET=TEST_SECRET)
class CooldownBridgePersistenceTests(TestCase):
    @patch("control.optix_proxy_bridge.time.time", return_value=2000000000)
    def test_authoritative_write_read_and_stale_replay(self, _clock):
        from .models import ProxyCooldownPolicy
        read = proxy_bridge(signed_request({"operation": "get", "actor": "dollar:staff"}))
        initial = json.loads(read.content)["policy"]
        self.assertTrue(initial["enabled"])
        values = {"operation": "set", "enabled": False, "expected_revision": initial["revision"], "actor": "dollar:admin"}
        written = proxy_bridge(signed_request(values))
        self.assertEqual(written.status_code, 200)
        policy = ProxyCooldownPolicy.objects.get(pk=1)
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.updated_by, "dollar:admin")
        self.assertEqual(proxy_bridge(signed_request(values)).status_code, 409)
        policy.refresh_from_db()
        self.assertEqual(policy.revision, initial["revision"] + 1)
