from __future__ import annotations

import base64
import hashlib
from typing import Any

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models

from .crypto import decrypt_json, decrypt_text, encrypt_json, encrypt_text


catalog_id_validator = RegexValidator(
    regex=r"^[A-Za-z0-9_-]{1,32}$",
    message="Use only letters, numbers, underscores, and hyphens.",
)


class ConfigBundle(models.Model):
    name = models.CharField(max_length=120, unique=True)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    browser_group_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Numeric browser group ID assigned to every device using this bundle.",
    )
    browser_group_name = models.CharField(
        max_length=160,
        default="Testing",
        help_text="Browser group name used for display and as a fallback when no ID is set.",
    )
    payload_ciphertext = models.TextField(blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} (v{self.version})"

    def set_payload(self, payload: dict[str, Any]) -> None:
        self.payload_ciphertext = encrypt_json(payload)

    def get_payload(self) -> dict[str, Any]:
        return decrypt_json(self.payload_ciphertext) if self.payload_ciphertext else {}


class ClientAccess(models.Model):
    name = models.CharField(max_length=120)
    ipv4 = models.GenericIPAddressField(protocol="IPv4")
    device_id = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Stable desktop identifier; leave blank for IP-only access.",
    )
    active = models.BooleanField(default=True)
    office_name = models.CharField(max_length=64)
    system_number = models.CharField(max_length=32)
    profile_name = models.CharField(
        max_length=160,
        blank=True,
        default="",
        help_text="Fixed browser profile name for this device. Defaults to the access-record name.",
    )
    config_bundle = models.ForeignKey(
        ConfigBundle,
        on_delete=models.PROTECT,
        related_name="clients",
    )
    notes = models.TextField(blank=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("office_name", "system_number", "name")
        verbose_name_plural = "Client access entries"
        constraints = [
            models.UniqueConstraint(
                fields=("ipv4", "device_id"),
                name="unique_ipv4_device_access",
            )
        ]

    def __str__(self) -> str:
        return f"{self.office_name} / sys_{self.system_number} / {self.ipv4}"


class Provider(models.Model):
    code = models.CharField(max_length=32, unique=True, validators=[catalog_id_validator])
    display_name = models.CharField(max_length=64)
    display_order = models.PositiveIntegerField(default=0)
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ("display_order", "code")

    def __str__(self) -> str:
        return self.display_name


class ProxyCountryFile(models.Model):
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="country_files",
    )
    country_code = models.CharField(max_length=32, validators=[catalog_id_validator])
    country_name = models.CharField(max_length=80)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    content_ciphertext = models.TextField(blank=True, editable=False)
    content_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("provider__display_order", "country_name")
        constraints = [
            models.UniqueConstraint(
                fields=("provider", "country_code"),
                name="unique_provider_country_file",
            )
        ]

    def __str__(self) -> str:
        return f"{self.provider.code} / {self.country_name}"

    def set_content(self, content: str) -> None:
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        self.content_ciphertext = encrypt_text(normalized)
        self.content_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def get_content(self) -> str:
        return decrypt_text(self.content_ciphertext) if self.content_ciphertext else ""


class ProxyRegionCatalog(models.Model):
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="region_catalog",
    )
    country_code = models.CharField(max_length=32, validators=[catalog_id_validator])
    region_code = models.CharField(max_length=120)
    region_name = models.CharField(max_length=160)
    source = models.CharField(max_length=40, blank=True, default="")
    active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("provider__display_order", "country_code", "region_name")
        constraints = [
            models.UniqueConstraint(
                fields=("provider", "country_code", "region_code"),
                name="unique_provider_country_region",
            )
        ]

    def __str__(self) -> str:
        return (
            f"{self.provider.code} / {self.country_code} / "
            f"{self.region_name}"
        )


class ExtensionPackage(models.Model):
    name = models.CharField(max_length=120, unique=True)
    filename = models.CharField(max_length=180)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)
    is_top = models.BooleanField(default=False)
    status = models.BooleanField(default=True)
    package_ciphertext = models.TextField(blank=True, editable=False)
    package_sha256 = models.CharField(max_length=64, blank=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} (v{self.version})"

    def set_package(self, raw: bytes) -> None:
        self.package_ciphertext = encrypt_text(base64.b64encode(raw).decode("ascii"))
        self.package_sha256 = hashlib.sha256(raw).hexdigest()

    def get_package(self) -> bytes:
        if not self.package_ciphertext:
            return b""
        return base64.b64decode(decrypt_text(self.package_ciphertext))


class ProxyPoolTarget(models.Model):
    config_bundle = models.ForeignKey(ConfigBundle, on_delete=models.CASCADE, related_name="proxy_pool_targets")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    target_count = models.PositiveIntegerField(default=1000)
    replenish_below = models.PositiveIntegerField(default=200)
    active = models.BooleanField(default=True)
    refill_pending = models.BooleanField(default=False, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("config_bundle", "provider_code", "country_code", "region", "city"), name="unique_proxy_pool_target")]


class ProxyPoolEntry(models.Model):
    target = models.ForeignKey(ProxyPoolTarget, on_delete=models.CASCADE, related_name="entries")
    proxy_fingerprint = models.CharField(max_length=64, unique=True)
    proxy_ciphertext = models.TextField(editable=False)
    state = models.CharField(max_length=16, default="available")
    exit_ip = models.GenericIPAddressField(blank=True, null=True)
    fraud_score = models.IntegerField(blank=True, null=True)
    reserved_client = models.ForeignKey(ClientAccess, on_delete=models.SET_NULL, blank=True, null=True, related_name="pool_entries")
    created_at = models.DateTimeField(auto_now_add=True)
    tested_at = models.DateTimeField(blank=True, null=True)
    reserved_at = models.DateTimeField(blank=True, null=True)

    def set_proxy(self, value: str) -> None:
        self.proxy_ciphertext = encrypt_text(value)

    def get_proxy(self) -> str:
        return decrypt_text(self.proxy_ciphertext)


class ProxyGenerationJob(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="proxy_jobs")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    requested_count = models.PositiveSmallIntegerField(default=1)
    ready_count = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=32, default="queued")
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ProxyReservation(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="proxy_reservations")
    job = models.ForeignKey(ProxyGenerationJob, on_delete=models.SET_NULL, null=True, blank=True, related_name="reservations")
    pool_entry = models.ForeignKey(ProxyPoolEntry, on_delete=models.SET_NULL, null=True, blank=True, related_name="reservations")
    provider_code = models.CharField(max_length=32)
    country_code = models.CharField(max_length=32)
    region = models.CharField(max_length=120, blank=True)
    city = models.CharField(max_length=120, blank=True)
    proxy_fingerprint = models.CharField(max_length=64, unique=True)
    proxy_ciphertext = models.TextField(blank=True, editable=False)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, blank=True)
    reserved_at = models.DateTimeField(auto_now_add=True)

    def set_proxy(self, value: str) -> None:
        self.proxy_ciphertext = encrypt_text(value)

    def get_proxy(self) -> str:
        return decrypt_text(self.proxy_ciphertext) if self.proxy_ciphertext else ""


class BrowserGroupMapping(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="browser_groups")
    browser_group_id = models.CharField(max_length=64)
    browser_group_name = models.CharField(max_length=160)
    internal_name = models.CharField(max_length=80, help_text="Your private management label.")
    is_default = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("client__office_name", "internal_name")
        constraints = [models.UniqueConstraint(fields=("client", "browser_group_id"), name="unique_client_browser_group")]

    def __str__(self) -> str:
        return f"{self.client} / {self.internal_name} ({self.browser_group_id})"


class ProfileActivity(models.Model):
    client = models.ForeignKey(ClientAccess, on_delete=models.CASCADE, related_name="profile_activity")
    job = models.ForeignKey(ProxyGenerationJob, on_delete=models.SET_NULL, null=True, blank=True, related_name="profile_activity")
    reservation = models.ForeignKey(ProxyReservation, on_delete=models.SET_NULL, null=True, blank=True, related_name="profile_activity")
    group_id = models.CharField(max_length=64, blank=True)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, blank=True)
    status = models.CharField(max_length=32)
    start_urls_json = models.TextField(blank=True)
    detail = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class ProfileDomainActivity(models.Model):
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.CASCADE,
        related_name="profile_domain_activity",
    )
    job = models.ForeignKey(
        ProxyGenerationJob,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="profile_domain_activity",
    )
    reservation = models.ForeignKey(
        ProxyReservation,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="profile_domain_activity",
    )
    session_id = models.CharField(max_length=64, db_index=True)
    group_id = models.CharField(max_length=64, blank=True, db_index=True)
    profile_name = models.CharField(max_length=160, blank=True)
    profile_id = models.CharField(max_length=128, db_index=True)
    browser_id = models.CharField(max_length=64, blank=True)
    domain = models.CharField(max_length=253, db_index=True)
    first_visited_at = models.DateTimeField()
    last_visited_at = models.DateTimeField()
    visit_count = models.PositiveIntegerField(default=1)
    session_started_at = models.DateTimeField()
    session_ended_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-last_visited_at", "domain")
        verbose_name_plural = "Profile domain activity"
        constraints = [
            models.UniqueConstraint(
                fields=("client", "profile_id", "session_id", "domain"),
                name="unique_profile_session_domain",
            )
        ]

    def __str__(self) -> str:
        return f"{self.profile_id} / {self.domain}"


class BootstrapAudit(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    client = models.ForeignKey(
        ClientAccess,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="audit_events",
    )
    observed_ip = models.GenericIPAddressField(blank=True, null=True)
    reported_ip = models.GenericIPAddressField(blank=True, null=True)
    device_id = models.CharField(max_length=128, blank=True)
    allowed = models.BooleanField(default=False)
    reason = models.CharField(max_length=80)
    app_version = models.CharField(max_length=40, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M} / {self.observed_ip} / {self.reason}"
class MonitoredDomain(models.Model):
    domain = models.CharField(max_length=253, unique=True)
    label = models.CharField(max_length=120, blank=True, default="")
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="monitored_domains",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("domain",)
        verbose_name = "Monitored domain"
        verbose_name_plural = "Monitored domains"

    def __str__(self) -> str:
        return self.domain


class SubAdminAccount(models.Model):
    """A non-staff account for the separate sub-admin dashboard."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="subadmin_account",
    )
    display_name = models.CharField(max_length=120, blank=True, default="")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = "Sub-admin account"
        verbose_name_plural = "Sub-admin accounts"
        ordering = ("user__username",)

    def __str__(self) -> str:
        return self.display_name.strip() or self.user.get_username()

class SubAdminDomainExclusion(models.Model):
    """Exact domain hidden from one sub-admin account."""

    account = models.ForeignKey(
        SubAdminAccount,
        on_delete=models.CASCADE,
        related_name="domain_exclusions",
    )
    domain = models.CharField(max_length=253)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("domain",)
        verbose_name = "Sub-admin domain exclusion"
        verbose_name_plural = "Sub-admin domain exclusions"
        constraints = [
            models.UniqueConstraint(
                fields=("account", "domain"),
                name="unique_subadmin_domain_exclusion",
            )
        ]

    def save(self, *args, **kwargs):
        self.domain = self.domain.strip().casefold().rstrip(".")
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.account} / {self.domain}"