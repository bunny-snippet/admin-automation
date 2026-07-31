from __future__ import annotations

import json

from django import forms
from django.contrib import admin

from .models import BootstrapAudit, ClientAccess, ConfigBundle, Provider, ProxyCountryFile


class ConfigBundleForm(forms.ModelForm):
    payload_json = forms.CharField(
        label="Encrypted configuration JSON",
        widget=forms.Textarea(attrs={"rows": 24, "cols": 100, "spellcheck": "false"}),
        help_text=(
            "Stored encrypted in PostgreSQL. It may contain every key formerly supplied "
            "through tubelight_config.txt. Never paste it into logs or support messages."
        ),
    )

    class Meta:
        model = ConfigBundle
        fields = ("name", "version", "active", "payload_json")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["payload_json"].initial = json.dumps(
                self.instance.get_payload(), indent=2, sort_keys=True
            )

    def clean_payload_json(self) -> dict:
        try:
            value = json.loads(self.cleaned_data["payload_json"])
        except json.JSONDecodeError as exc:
            raise forms.ValidationError(f"Invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise forms.ValidationError("Configuration must be a JSON object.")
        return value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_payload(self.cleaned_data["payload_json"])
        if commit:
            instance.save()
        return instance


class ProxyCountryFileForm(forms.ModelForm):
    proxy_text = forms.CharField(
        label="Encrypted proxy TXT content",
        widget=forms.Textarea(attrs={"rows": 24, "cols": 100, "spellcheck": "false"}),
        help_text="Content is returned exactly to an authorized app and stored encrypted.",
    )

    class Meta:
        model = ProxyCountryFile
        fields = (
            "provider",
            "country_code",
            "country_name",
            "version",
            "active",
            "proxy_text",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["proxy_text"].initial = self.instance.get_content()

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_content(self.cleaned_data["proxy_text"])
        if commit:
            instance.save()
        return instance


@admin.register(ConfigBundle)
class ConfigBundleAdmin(admin.ModelAdmin):
    form = ConfigBundleForm
    list_display = ("name", "version", "active", "updated_at")
    list_filter = ("active",)


@admin.register(ClientAccess)
class ClientAccessAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "ipv4",
        "device_id",
        "office_name",
        "system_number",
        "config_bundle",
        "active",
        "last_seen_at",
    )
    list_filter = ("active", "office_name", "config_bundle")
    search_fields = ("name", "ipv4", "device_id", "office_name", "system_number")


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ("code", "display_name", "display_order", "active")
    list_editable = ("display_name", "display_order", "active")


@admin.register(ProxyCountryFile)
class ProxyCountryFileAdmin(admin.ModelAdmin):
    form = ProxyCountryFileForm
    list_display = (
        "provider",
        "country_code",
        "country_name",
        "version",
        "active",
        "updated_at",
    )
    list_filter = ("provider", "active")
    search_fields = ("provider__code", "country_code", "country_name")


@admin.register(BootstrapAudit)
class BootstrapAuditAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "observed_ip",
        "reported_ip",
        "device_id",
        "client",
        "allowed",
        "reason",
        "app_version",
    )
    list_filter = ("allowed", "reason")
    search_fields = ("observed_ip", "reported_ip", "device_id", "client__name", "app_version")
    readonly_fields = (
        "created_at",
        "client",
        "observed_ip",
        "reported_ip",
        "device_id",
        "allowed",
        "reason",
        "app_version",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
