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
from django.utils.html import format_html

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
    """Import TXT files from a browser ZIP, replacing existing provider/country rows."""
    imported = 0
    replaced = 0
    total_size = 0
    try:
        archive = zipfile.ZipFile(upload)
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc

    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir() and info.filename.lower().endswith(".txt")]
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
            parts = [part for part in PurePosixPath(info.filename).parts if part not in {"", ".", ".."}]
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
            provider, _ = Provider.objects.get_or_create(
                code=provider_code,
                defaults={"display_name": provider_code, "display_order": 0, "active": True},
            )
            provider.active = True
            provider.save(update_fields=("active",))
            row, created = ProxyCountryFile.objects.get_or_create(
                provider=provider,
                country_code=country_code,
                defaults={"country_name": country_name, "active": True},
            )
            if not created:
                row.version += 1
                replaced += 1
            row.country_name = country_name
            row.active = True
            row.set_content(content)
            row.save()
            imported += 1
    return imported, replaced


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
