from __future__ import annotations

import json
from datetime import timedelta
from threading import Barrier, Lock, Thread
from unittest import mock

from django.core import signing
from django.db import IntegrityError, close_old_connections, transaction
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from .exit_ip_cooldown import (
    check_exit_ip,
    claim_exit_ip,
    cooldown_policy_payload,
    set_cooldown_policy,
)
from .models import (
    ClientAccess,
    ConfigBundle,
    ProxyCooldownPolicy,
    ProxyExitIPCooldown,
    ProxyGenerationJob,
    ProxyReservation,
)
from .views import TOKEN_SALT, proxy_exit_ip_claim


@override_settings(PROXY_EXIT_IP_COOLDOWN_SECONDS=90000)
class CooldownPolicyTests(TestCase):
    def setUp(self):
        ProxyCooldownPolicy.objects.update_or_create(pk=1, defaults={
            "enabled": True, "revision": 0, "updated_at": None, "updated_by": "",
        })
        bundle = ConfigBundle(name="Cooldown policy test", version=1)
        bundle.set_payload({})
        bundle.save()
        self.clients = [ClientAccess.objects.create(
            name=f"Cooldown device {i}", ipv4=f"203.0.113.{i + 10}",
            device_id=f"cooldown-device-{i}", office_name=f"Office {i}",
            system_number=str(i), config_bundle=bundle,
        ) for i in range(2)]
        self.reservations = []
        for index, client in enumerate(self.clients):
            job = ProxyGenerationJob.objects.create(client=client, provider_code=f"P{index + 1}", country_code="US")
            self.reservations.append(ProxyReservation.objects.create(
                client=client, job=job, provider_code=job.provider_code, country_code="US",
                proxy_fingerprint=f"policy-reservation-{index}",
            ))
        self.now = timezone.now()

    def claim(self, index=0, *, at=None, ip="198.51.100.20", **kwargs):
        reservation = self.reservations[index]
        return claim_exit_ip(client=self.clients[index], provider_code=reservation.provider_code,
            exit_ip=ip, job=reservation.job, reservation=reservation, now=at or self.now, **kwargs)

    def api(self, body, *, authenticated=True, provider_allowed=True, optix=True):
        request = RequestFactory().post("/api/v1/proxy-exit-claims/",
            data=json.dumps(body), content_type="application/json")
        request._optix_cooldown_policy = optix
        with mock.patch("control.views._authenticated_client",
                return_value=self.clients[0], side_effect=None if authenticated else signing.BadSignature()), \
                mock.patch("control.views._provider_is_allowed", return_value=provider_allowed):
            response = proxy_exit_ip_claim(request)
        return response.status_code, json.loads(response.content)

    def test_default_is_on_and_missing_singleton_is_fail_closed_without_read_writes(self):
        expected = {"enabled": True, "cooldown_hours": 25, "updated_at": None, "revision": 0}
        self.assertEqual(cooldown_policy_payload(), expected)
        ProxyCooldownPolicy.objects.all().delete()
        self.assertEqual(cooldown_policy_payload(), expected)
        self.assertFalse(ProxyCooldownPolicy.objects.exists())
        self.claim()
        self.assertFalse(self.claim(1).claimed)

    def test_setter_validates_boolean_and_revision_and_rejects_stale_updates(self):
        for enabled in (0, 1, "false", "true", None, [], {}):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                set_cooldown_policy(enabled)
        for revision in (False, -1, "0", 1.5):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                set_cooldown_policy(False, expected_revision=revision)
        self.assertEqual(cooldown_policy_payload()["revision"], 0)
        changed = set_cooldown_policy(False, actor="test-admin", expected_revision=0)
        self.assertEqual(changed["revision"], 1)
        self.assertFalse(changed["enabled"])
        self.assertIsNotNone(changed["updated_at"])
        self.assertEqual(ProxyCooldownPolicy.objects.get().updated_by, "test-admin")
        with self.assertRaises(ValueError):
            set_cooldown_policy(True, actor="stale-admin", expected_revision=0)
        self.assertEqual(cooldown_policy_payload(), changed)
        self.assertEqual(ProxyCooldownPolicy.objects.get().updated_by, "test-admin")

    def test_database_rejects_a_second_policy_identity(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ProxyCooldownPolicy.objects.create(pk=2)
        self.assertEqual(ProxyCooldownPolicy.objects.count(), 1)

    def test_on_is_global_across_offices_and_providers_and_rejection_keeps_window(self):
        accepted = self.claim()
        before = (accepted.cooldown.claimed_at, accepted.cooldown.available_after)
        duplicate = self.claim(1, at=self.now + timedelta(seconds=30))
        self.assertTrue(accepted.claimed)
        self.assertTrue(accepted.cooldown_enabled)
        self.assertFalse(duplicate.claimed)
        self.assertTrue(check_exit_ip(exit_ip="198.51.100.20", reservation=self.reservations[1], now=self.now).duplicate)
        self.assertEqual((duplicate.cooldown.claimed_at, duplicate.cooldown.available_after), before)

    def test_off_bypasses_history_but_records_new_success_and_reenable_uses_it(self):
        first = self.claim()
        self.claim(1, at=self.now + timedelta(seconds=1))
        original_count = ProxyExitIPCooldown.objects.count()
        set_cooldown_policy(False)
        first.cooldown.refresh_from_db()
        self.assertEqual(first.cooldown.claimed_at, self.now, "Changing policy must not rewrite history")
        off_check = check_exit_ip(exit_ip="198.51.100.20", reservation=self.reservations[1], now=self.now)
        self.assertFalse(off_check.cooldown_enabled)
        self.assertFalse(off_check.duplicate)
        second_time = self.now + timedelta(minutes=5)
        second = self.claim(1, at=second_time)
        self.assertTrue(second.claimed)
        self.assertFalse(second.cooldown_enabled)
        self.assertEqual(second.cooldown.pk, first.cooldown.pk)
        self.assertEqual(second.cooldown.claimed_at, second_time)
        self.assertEqual(second.cooldown.available_after, second_time + timedelta(hours=25))
        self.assertEqual(second.cooldown.client_id, self.clients[1].pk)
        self.assertEqual(second.cooldown.duplicate_attempts, 1)
        self.assertEqual(ProxyExitIPCooldown.objects.count(), original_count)
        set_cooldown_policy(True)
        check = check_exit_ip(exit_ip="198.51.100.20", reservation=self.reservations[0], now=second_time)
        self.assertTrue(check.cooldown_enabled)
        self.assertTrue(check.duplicate)
        self.assertFalse(self.claim(0, at=second_time + timedelta(hours=25, microseconds=-1)).claimed)
        self.assertTrue(self.claim(0, at=second_time + timedelta(hours=25)).claimed)

    def test_off_new_address_is_recorded_and_same_reservation_retry_remains_idempotent(self):
        set_cooldown_policy(False)
        first = self.claim(fraud_score=20)
        retry = self.claim(at=self.now + timedelta(minutes=2), fraud_score=15)
        self.assertTrue(first.claimed)
        self.assertTrue(retry.claimed)
        self.assertTrue(retry.idempotent)
        self.assertFalse(retry.cooldown_enabled)
        self.assertEqual(retry.cooldown.claimed_at, self.now)
        self.assertEqual(retry.cooldown.available_after, first.cooldown.available_after)
        self.assertEqual(retry.cooldown.fraud_score, 15)
        self.assertEqual(ProxyExitIPCooldown.objects.count(), 1)

    def test_off_does_not_bypass_ip_or_quality_input_validation(self):
        set_cooldown_policy(False)
        for values in ({"ip": "not-an-ip"}, {"fraud_score": -1}, {"fraud_score": 101}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.claim(**values)
        self.assertFalse(ProxyExitIPCooldown.objects.exists())

    def test_api_off_check_and_claim_return_explicit_flag_and_zero_retry_delay(self):
        self.claim(1)
        set_cooldown_policy(False)
        payload = {"provider": "P1", "exit_ip": "198.51.100.20"}
        status, checked = self.api({**payload, "action": "check"})
        self.assertEqual(status, 200)
        self.assertFalse(checked["cooldown_enabled"])
        self.assertFalse(checked["duplicate"])
        self.assertEqual(checked["retry_after_seconds"], 0)
        self.assertIn("available_after", checked)
        self.assertNotIn("reason", checked)
        status, claimed = self.api(payload)
        self.assertEqual(status, 200)
        self.assertTrue(claimed["claimed"])
        self.assertFalse(claimed["cooldown_enabled"])
        self.assertEqual(claimed["retry_after_seconds"], 0)
        set_cooldown_policy(True)
        status, checked = self.api({**payload, "action": "check"})
        self.assertEqual(status, 200)
        self.assertTrue(checked["cooldown_enabled"])
        self.assertTrue(checked["duplicate"])
        self.assertGreater(checked["retry_after_seconds"], 0)

    def test_api_off_preserves_auth_provider_ownership_and_payload_checks(self):
        set_cooldown_policy(False)
        valid = {"provider": "P1", "exit_ip": "198.51.100.20"}
        self.assertEqual(self.api(valid, authenticated=False)[0], 403)
        self.assertEqual(self.api(valid, provider_allowed=False)[0], 400)
        self.assertEqual(self.api({**valid, "reservation_id": self.reservations[1].pk})[0], 403)
        self.assertEqual(self.api({**valid, "job_id": self.reservations[1].job_id})[0], 403)
        self.assertEqual(self.api({**valid, "exit_ip": "invalid"})[0], 400)
        self.assertEqual(self.api({**valid, "fraud_score": 101})[0], 400)
        self.assertEqual(self.api({**valid, "action": "disable"})[0], 400)
        self.assertFalse(ProxyExitIPCooldown.objects.exists())

    def test_legacy_api_and_explicit_helper_scope_keep_cooldown_on_when_policy_off(self):
        self.claim(1)
        set_cooldown_policy(False)
        for action in ("check", "claim"):
            status, result = self.api({"provider": "P1", "exit_ip": "198.51.100.20", "action": action}, optix=False)
            self.assertEqual(status, 200)
            self.assertTrue(result["cooldown_enabled"])
            self.assertTrue(result["duplicate"])
            self.assertGreater(result["retry_after_seconds"], 0)
        checked = check_exit_ip(exit_ip="198.51.100.20", apply_global_policy=False, now=self.now)
        self.assertTrue(checked.cooldown_enabled)
        self.assertTrue(checked.duplicate)
        claimed = self.claim(0, apply_global_policy=False)
        self.assertTrue(claimed.cooldown_enabled)
        self.assertFalse(claimed.claimed)

    @override_settings(TRUST_APP_REPORTED_IPV4=False, LOCAL_TESTING_MODE=False)
    def test_policy_scope_uses_verified_token_not_client_metadata_or_header(self):
        self.claim(1)
        set_cooldown_policy(False)
        client = self.clients[0]
        client.desktop_client_product = ClientAccess.DESKTOP_PRODUCT_OPTIX
        client.save(update_fields=("desktop_client_product",))
        for product, expected_enabled in ((None, True), ("unknown", True), ("optix", False)):
            payload = {"client_id": client.pk, "ip": client.ipv4, "device_id": client.device_id,
                "config_version": client.config_bundle.version}
            if product is not None:
                payload["browser_catalog_product"] = product
            token = signing.dumps(payload, salt=TOKEN_SALT)
            request = RequestFactory().post("/api/v1/proxy-exit-claims/", data=json.dumps({
                "provider": "P1", "exit_ip": "198.51.100.20", "action": "check",
                "browser_catalog_product": "optix", "cooldown_enabled": False,
            }), content_type="application/json", REMOTE_ADDR=client.ipv4,
                HTTP_X_DEVICE_ID=client.device_id, HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_X_APP_PRODUCT="optix")
            with mock.patch("control.views._provider_is_allowed", return_value=True):
                response = proxy_exit_ip_claim(request)
            self.assertEqual(response.status_code, 200)
            result = json.loads(response.content)
            self.assertEqual(result["cooldown_enabled"], expected_enabled)
            self.assertEqual(result["duplicate"], expected_enabled)

    def test_authenticated_private_bridge_can_apply_policy_without_electron_token(self):
        self.claim(1)
        set_cooldown_policy(False)
        request = RequestFactory().post("/api/v1/proxy-exit-claims/", data=json.dumps({
            "provider": "P1", "exit_ip": "198.51.100.20", "action": "check",
        }), content_type="application/json")
        request._optix_trusted_client = self.clients[0]
        request._optix_bridge_request = True
        with mock.patch("control.views._provider_is_allowed", return_value=True):
            response = proxy_exit_ip_claim(request)
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.content)
        self.assertFalse(result["cooldown_enabled"])
        self.assertFalse(result["duplicate"])


class CooldownPolicyConcurrencyTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_two_admin_writes_using_same_revision_have_one_winner(self):
        ProxyCooldownPolicy.objects.update_or_create(pk=1, defaults={"enabled": True, "revision": 0})
        barrier = Barrier(2)
        lock = Lock()
        outcomes = []

        def writer():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                set_cooldown_policy(False, expected_revision=0)
                outcome = "saved"
            except ValueError:
                outcome = "stale"
            except Exception as error:
                outcome = type(error).__name__
            finally:
                close_old_connections()
            with lock:
                outcomes.append(outcome)

        threads = [Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertCountEqual(outcomes, ["saved", "stale"])
        self.assertEqual(cooldown_policy_payload()["revision"], 1)
