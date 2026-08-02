from __future__ import annotations

import json
import re
import zipfile
from pathlib import PurePosixPath


from django import forms
from django.contrib import admin, messages
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html

from .models import (BootstrapAudit, ClientAccess, ConfigBundle, ExtensionPackage, Provider, ProxyCountryFile, ProxyGenerationJob, ProxyReservation, ProfileActivity, ProfileDomainActivity, BrowserGroupMapping, ProxyPoolTarget, ProxyPoolEntry)


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


SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MAX_CATALOG_FILES = 5_000
MAX_CATALOG_FILE_BYTES = 3 * 1024 * 1024
MAX_CATALOG_TOTAL_BYTES = 30 * 1024 * 1024


class CatalogZipUploadForm(forms.Form):
    catalog_zip = forms.FileField(
        label="Proxy catalog ZIP",
        help_text="Use P1/US.txt or proxy/P1/US__United States.txt paths inside the ZIP.",
    )

    def clean_catalog_zip(self):
        upload = self.cleaned_data["catalog_zip"]
        if not upload.name.lower().endswith(".zip"):
            raise forms.ValidationError("Upload a .zip file.")
        return upload


def _country_from_filename(filename: str) -> tuple[str, str]:
    stem = PurePosixPath(filename).stem.strip()
    if "__" in stem:
        country_code, country_name = stem.split("__", 1)
    else:
        country_code = re.sub(r"[^A-Za-z0-9_-]+", "-", stem).strip("-")
        country_name = stem.replace("_", " ").replace("-", " ").strip().title()
    if not SAFE_ID.fullmatch(country_code):
        raise ValueError(f"Unsafe country code: {filename}")
    return country_code, country_name or country_code


@transaction.atomic
def import_catalog_zip(upload, only_provider: str | None = None) -> tuple[int, int]:
    """Import a browser ZIP with batched writes, replacing matching country rows."""
    total_size = 0
    records: dict[tuple[str, str], tuple[str, str]] = {}
    try:
        archive = zipfile.ZipFile(upload)
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc

    with archive:
        entries = [
            info for info in archive.infolist()
            if not info.is_dir() and info.filename.lower().endswith(".txt")
        ]
        if not entries:
            raise ValueError("The ZIP does not contain any TXT files.")
        if len(entries) > MAX_CATALOG_FILES:
            raise ValueError("Too many TXT files in one ZIP.")
        for info in entries:
            if info.file_size > MAX_CATALOG_FILE_BYTES:
                raise ValueError(f"TXT file is too large: {info.filename}")
            total_size += info.file_size
            if total_size > MAX_CATALOG_TOTAL_BYTES:
                raise ValueError("Total ZIP TXT content is too large.")
            parts = [
                part for part in PurePosixPath(info.filename).parts
                if part not in {"", ".", ".."}
            ]
            if only_provider:
                if len(parts) >= 2 and parts[-2] == only_provider:
                    provider_code, filename = only_provider, parts[-1]
                elif len(parts) == 1:
                    provider_code, filename = only_provider, parts[-1]
                else:
                    continue
            else:
                if len(parts) < 2:
                    raise ValueError(f"Use P1/US.txt style paths: {info.filename}")
                provider_code, filename = parts[-2], parts[-1]
            if not SAFE_ID.fullmatch(provider_code):
                raise ValueError(f"Unsafe provider code: {provider_code}")
            country_code, country_name = _country_from_filename(filename)
            try:
                content = archive.read(info).decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError(f"TXT must be UTF-8: {info.filename}") from exc
            records[(provider_code, country_code)] = (country_name, content)

    if not records:
        raise ValueError("No TXT files matched this provider.")

    provider_codes = sorted({provider_code for provider_code, _ in records})
    existing_providers = {item.code: item for item in Provider.objects.filter(code__in=provider_codes)}
    Provider.objects.bulk_create(
        [
            Provider(code=code, display_name=code, display_order=0, active=True)
            for code in provider_codes if code not in existing_providers
        ],
        ignore_conflicts=True,
        batch_size=100,
    )
    Provider.objects.filter(code__in=provider_codes).update(active=True)
    providers = {item.code: item for item in Provider.objects.filter(code__in=provider_codes)}

    provider_ids = [item.pk for item in providers.values()]
    country_codes = {country_code for _, country_code in records}
    existing_rows = {
        (item.provider_id, item.country_code): item
        for item in ProxyCountryFile.objects.filter(
            provider_id__in=provider_ids,
            country_code__in=country_codes,
        )
    }
    now = timezone.now()
    new_rows: list[ProxyCountryFile] = []
    changed_rows: list[ProxyCountryFile] = []
    replaced = 0
    for (provider_code, country_code), (country_name, content) in records.items():
        provider = providers[provider_code]
        row = existing_rows.get((provider.pk, country_code))
        if row is None:
            row = ProxyCountryFile(
                provider=provider,
                country_code=country_code,
                country_name=country_name,
                active=True,
            )
            row.set_content(content)
            new_rows.append(row)
        else:
            row.version += 1
            row.country_name = country_name
            row.active = True
            row.updated_at = now
            row.set_content(content)
            changed_rows.append(row)
            replaced += 1
    if new_rows:
        ProxyCountryFile.objects.bulk_create(new_rows, batch_size=100)
    if changed_rows:
        ProxyCountryFile.objects.bulk_update(
            changed_rows,
            ["country_name", "version", "active", "content_ciphertext", "content_sha256", "updated_at"],
            batch_size=100,
        )
    return len(records), replaced


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
    change_list_template = "admin/control/provider/change_list.html"
    list_display = ("code", "display_name", "display_order", "active", "country_files_link", "upload_countries_link")
    list_editable = ("display_name", "display_order", "active")

    def get_urls(self):
        custom = [
            path("upload-catalog/", self.admin_site.admin_view(self.upload_catalog_view), name="control_provider_upload_catalog"),
            path("<int:provider_id>/upload-catalog/", self.admin_site.admin_view(self.upload_catalog_view), name="control_provider_upload_countries"),
        ]
        return custom + super().get_urls()

    @admin.display(description="Countries")
    def country_files_link(self, obj):
        url = reverse("admin:control_proxycountryfile_changelist") + f"?provider__id__exact={obj.pk}"
        return format_html('<a href="{}">View country TXT files</a>', url)

    @admin.display(description="Upload")
    def upload_countries_link(self, obj):
        url = reverse("admin:control_provider_upload_countries", args=(obj.pk,))
        return format_html('<a class="button" href="{}">Upload / replace</a>', url)

    def upload_catalog_view(self, request: HttpRequest, provider_id: int | None = None) -> HttpResponse:
        provider = get_object_or_404(Provider, pk=provider_id) if provider_id is not None else None
        if request.method == "POST":
            form = CatalogZipUploadForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    imported, replaced = import_catalog_zip(form.cleaned_data["catalog_zip"], provider.code if provider else None)
                except ValueError as exc:
                    form.add_error("catalog_zip", str(exc))
                else:
                    messages.success(request, f"Imported {imported} TXT file(s); replaced {replaced} existing country file(s).")
                    return redirect("admin:control_provider_changelist" if provider is None else reverse("admin:control_proxycountryfile_changelist") + f"?provider__id__exact={provider.pk}")
        else:
            form = CatalogZipUploadForm()
        rows = provider.country_files.all() if provider else ()
        return TemplateResponse(request, "admin/control/provider/upload_catalog.html", {**self.admin_site.each_context(request), "title": "Upload proxy catalog" if provider is None else f"Upload countries for {provider.code}", "form": form, "provider": provider, "rows": rows})


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


class ExtensionPackageForm(forms.ModelForm):
    package_zip = forms.FileField(required=False, label="Extension ZIP package")

    class Meta:
        model = ExtensionPackage
        fields = ("name", "filename", "version", "active", "is_top", "status", "package_zip")

    def clean_package_zip(self):
        upload = self.cleaned_data.get("package_zip")
        if upload is not None and not upload.name.lower().endswith(".zip"):
            raise forms.ValidationError("Extension package must be a ZIP file.")
        if upload is not None and upload.size > 20 * 1024 * 1024:
            raise forms.ValidationError("Extension ZIP must be 20 MB or smaller.")
        if not self.instance.pk and upload is None:
            raise forms.ValidationError("Upload an extension ZIP package.")
        return upload

    def save(self, commit=True):
        instance = super().save(commit=False)
        upload = self.cleaned_data.get("package_zip")
        if upload is not None:
            instance.filename = upload.name
            instance.set_package(upload.read())
        if commit:
            instance.save()
        return instance


@admin.register(ExtensionPackage)
class ExtensionPackageAdmin(admin.ModelAdmin):
    form = ExtensionPackageForm
    list_display = ("name", "filename", "version", "active", "status", "is_top", "updated_at")
    list_editable = ("active", "status", "is_top")
    readonly_fields = ("package_sha256", "updated_at")


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


@admin.register(ProxyGenerationJob)
class ProxyGenerationJobAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "provider_code", "country_code", "region", "city", "requested_count", "ready_count", "status", "created_at")
    list_filter = ("status", "provider_code", "country_code")
    search_fields = ("client__name", "client__office_name", "client__system_number")
    readonly_fields = ("client", "provider_code", "country_code", "region", "city", "requested_count", "ready_count", "status", "error", "created_at", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyReservation)
class ProxyReservationAdmin(admin.ModelAdmin):
    list_display = ("id", "client", "job", "provider_code", "country_code", "region", "city", "profile_name", "profile_id", "reserved_at")
    list_filter = ("provider_code", "country_code")
    search_fields = ("client__name", "client__office_name", "profile_name", "profile_id", "proxy_fingerprint")
    readonly_fields = ("client", "job", "provider_code", "country_code", "region", "city", "proxy_fingerprint", "proxy_ciphertext", "profile_name", "profile_id", "reserved_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProfileActivity)
class ProfileActivityAdmin(admin.ModelAdmin):
    list_display = ("created_at", "client", "job", "reservation", "group_id", "profile_name", "profile_id", "status")
    list_filter = ("status", "group_id")
    search_fields = ("client__name", "client__office_name", "profile_name", "profile_id", "detail")
    readonly_fields = ("created_at", "client", "job", "reservation", "group_id", "profile_name", "profile_id", "status", "start_urls_json", "detail")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BrowserGroupMapping)
class BrowserGroupMappingAdmin(admin.ModelAdmin):
    list_display = ("internal_name", "browser_group_name", "browser_group_id", "client", "is_default", "active", "updated_at")
    list_filter = ("is_default", "active", "client__office_name")
    search_fields = ("internal_name", "browser_group_name", "browser_group_id", "client__ipv4", "client__device_id")
    list_editable = ("is_default", "active")


def _client_ip(obj):
    return obj.client.ipv4
_client_ip.short_description = "Client IP"


def _device_id(obj):
    return obj.client.device_id
_device_id.short_description = "Device ID"


ProfileActivityAdmin.list_display = ("created_at", _client_ip, _device_id, "client", "group_id", "profile_name", "profile_id", "status")
ProfileActivityAdmin.list_filter = ("status", "group_id", "client__office_name", "client__ipv4")
ProfileActivityAdmin.search_fields = ("client__ipv4", "client__device_id", "client__office_name", "profile_name", "profile_id", "start_urls_json", "detail")


@admin.register(ProfileDomainActivity)
class ProfileDomainActivityAdmin(admin.ModelAdmin):
    list_display = (
        "last_visited_at",
        "domain",
        _client_ip,
        _device_id,
        "client",
        "group_id",
        "profile_name",
        "profile_id",
        "visit_count",
    )
    list_filter = (
        ("last_visited_at", admin.DateFieldListFilter),
        "group_id",
        "client__office_name",
        "client__ipv4",
    )
    search_fields = (
        "domain",
        "client__ipv4",
        "client__device_id",
        "client__office_name",
        "profile_name",
        "profile_id",
        "browser_id",
        "session_id",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
        "client",
        "job",
        "reservation",
        "session_id",
        "group_id",
        "profile_name",
        "profile_id",
        "browser_id",
        "domain",
        "first_visited_at",
        "last_visited_at",
        "visit_count",
        "session_started_at",
        "session_ended_at",
    )
    list_select_related = ("client", "job", "reservation")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ProxyPoolTarget)
class ProxyPoolTargetAdmin(admin.ModelAdmin):
    list_display = ("provider_code", "country_code", "region", "city", "config_bundle", "target_count", "replenish_below", "active", "available_entries")
    list_filter = ("provider_code", "country_code", "active")
    search_fields = ("provider_code", "country_code", "region", "city", "config_bundle__name")
    list_select_related = ("config_bundle",)

    @admin.display(description="Available")
    def available_entries(self, obj):
        return obj.entries.filter(state="available").count()


@admin.register(ProxyPoolEntry)
class ProxyPoolEntryAdmin(admin.ModelAdmin):
    list_display = ("target", "state", "exit_ip", "fraud_score", "reserved_client", "created_at", "reserved_at")
    list_filter = ("state", "target__provider_code", "target__country_code")
    search_fields = ("proxy_fingerprint", "exit_ip", "reserved_client__device_id")
    readonly_fields = ("proxy_fingerprint", "proxy_ciphertext", "created_at", "tested_at", "reserved_at")
    list_select_related = ("target", "reserved_client")
