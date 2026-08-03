from __future__ import annotations

from typing import Any, Callable

from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.http import require_GET

from .models import (
    BootstrapAudit,
    BrowserGroupMapping,
    ClientAccess,
    ConfigBundle,
    ExtensionPackage,
    ProfileActivity,
    Provider,
    ProxyCountryFile,
    ProxyGenerationJob,
    ProxyPoolEntry,
    ProxyPoolTarget,
    ProxyReservation,
)
from .panel_views import admin_change, bounded_int, iso, panel_json


def _column(key: str, label: str, kind: str = "text") -> dict[str, str]:
    return {"key": key, "label": label, "type": kind}


def _resource_page(
    request: HttpRequest,
    queryset,
    serializer: Callable[[Any], dict[str, Any]],
    *,
    title: str,
    description: str,
    columns: list[dict[str, str]],
    admin_url: str,
) -> JsonResponse:
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    return panel_json(
        {
            "title": title,
            "description": description,
            "columns": columns + [_column("admin_url", "", "action")],
            "rows": [serializer(row) for row in page.object_list],
            "admin_url": admin_url,
            "pagination": {
                "page": page.number,
                "pages": paginator.num_pages,
                "page_size": page_size,
                "total": paginator.count,
                "has_previous": page.has_previous(),
                "has_next": page.has_next(),
            },
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_resource_api(request: HttpRequest, resource: str) -> JsonResponse:
    query = str(request.GET.get("q") or "").strip()
    t = lambda key, label: _column(key, label)
    d = lambda key, label: _column(key, label, "date")
    s = lambda key, label: _column(key, label, "status")

    if resource == "devices":
        queryset = ClientAccess.objects.select_related("config_bundle")
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(ipv4__icontains=query)
                | Q(device_id__icontains=query)
                | Q(office_name__icontains=query)
                | Q(profile_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("office_name", "system_number"),
            lambda row: {
                "name": row.name,
                "office": row.office_name,
                "system": row.system_number,
                "ipv4": str(row.ipv4),
                "device_id": row.device_id,
                "profile_name": row.profile_name or row.name,
                "config": row.config_bundle.name,
                "active": row.active,
                "last_seen": iso(row.last_seen_at),
                "admin_url": admin_change("clientaccess", row.pk),
            },
            title="Devices",
            description="Whitelisted systems, identity, office and profile assignments.",
            columns=[
                t("name", "Device"), t("office", "Office"), t("system", "System"),
                t("ipv4", "Public IP"), t("device_id", "Device ID"),
                t("profile_name", "Profile name"), t("config", "Config"),
                s("active", "Active"), d("last_seen", "Last seen"),
            ],
            admin_url=reverse("admin:control_clientaccess_changelist"),
        )

    if resource == "configurations":
        queryset = ConfigBundle.objects.annotate(client_count=Count("clients"))
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(browser_group_name__icontains=query)
                | Q(browser_group_id__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("name"),
            lambda row: {
                "name": row.name,
                "version": row.version,
                "group_name": row.browser_group_name,
                "group_id": row.browser_group_id or "Testing fallback",
                "clients": row.client_count,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("configbundle", row.pk),
            },
            title="Configuration bundles",
            description="Encrypted settings and fixed office group assignments.",
            columns=[
                t("name", "Bundle"), t("version", "Version"),
                t("group_name", "Group"), t("group_id", "Group ID"),
                t("clients", "Devices"), s("active", "Active"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_configbundle_changelist"),
        )

    if resource == "groups":
        queryset = BrowserGroupMapping.objects.select_related("client")
        if query:
            queryset = queryset.filter(
                Q(internal_name__icontains=query)
                | Q(browser_group_name__icontains=query)
                | Q(browser_group_id__icontains=query)
                | Q(client__name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "internal_name": row.internal_name,
                "browser_name": row.browser_group_name,
                "group_id": row.browser_group_id,
                "client": row.client.name,
                "office": row.client.office_name,
                "default": row.is_default,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("browsergroupmapping", row.pk),
            },
            title="Browser groups",
            description="Known group IDs and internal office labels.",
            columns=[
                t("internal_name", "Internal label"),
                t("browser_name", "Browser group"), t("group_id", "Group ID"),
                t("client", "Device"), t("office", "Office"),
                s("default", "Default"), s("active", "Active"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_browsergroupmapping_changelist"),
        )

    if resource == "providers":
        queryset = Provider.objects.annotate(
            country_count=Count("country_files")
        ).order_by("display_order", "code")
        if query:
            queryset = queryset.filter(
                Q(code__icontains=query) | Q(display_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "code": row.code,
                "name": row.display_name,
                "countries": row.country_count,
                "order": row.display_order,
                "active": row.active,
                "admin_url": admin_change("provider", row.pk),
            },
            title="Providers",
            description="Visible provider codes and uploaded country coverage.",
            columns=[
                t("code", "Code"), t("name", "Display name"),
                t("countries", "Countries"), t("order", "Order"),
                s("active", "Active"),
            ],
            admin_url=reverse("admin:control_provider_changelist"),
        )

    if resource == "proxy-catalog":
        queryset = ProxyCountryFile.objects.select_related("provider")
        if query:
            queryset = queryset.filter(
                Q(provider__code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(country_name__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "provider": row.provider.code,
                "country": row.country_name,
                "country_code": row.country_code,
                "version": row.version,
                "active": row.active,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("proxycountryfile", row.pk),
            },
            title="Proxy catalog",
            description="Encrypted country TXT inventories available to clients.",
            columns=[
                t("provider", "Provider"), t("country", "Country"),
                t("country_code", "Code"), t("version", "Version"),
                s("active", "Active"), d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_proxycountryfile_changelist"),
        )

    if resource == "extensions":
        queryset = ExtensionPackage.objects.all()
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query)
                | Q(filename__icontains=query)
                | Q(package_sha256__icontains=query)
            )
        return _resource_page(
            request,
            queryset,
            lambda row: {
                "name": row.name,
                "filename": row.filename,
                "version": row.version,
                "active": row.active,
                "status": row.status,
                "top": row.is_top,
                "updated_at": iso(row.updated_at),
                "admin_url": admin_change("extensionpackage", row.pk),
            },
            title="Extensions",
            description="Managed extension ZIPs delivered to authorized clients.",
            columns=[
                t("name", "Extension"), t("filename", "Package"),
                t("version", "Version"), s("active", "Active"),
                s("status", "Enabled"), s("top", "Priority"),
                d("updated_at", "Updated"),
            ],
            admin_url=reverse("admin:control_extensionpackage_changelist"),
        )

    if resource == "proxy-pools":
        queryset = ProxyPoolTarget.objects.select_related("config_bundle").annotate(
            available_count=Count("entries", filter=Q(entries__state="available")),
            reserved_count=Count("entries", filter=Q(entries__state="reserved")),
        )
        if query:
            queryset = queryset.filter(
                Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(region__icontains=query)
                | Q(city__icontains=query)
                | Q(config_bundle__name__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("provider_code", "country_code"),
            lambda row: {
                "provider": row.provider_code,
                "country": row.country_code,
                "location": " / ".join(
                    value for value in (row.region, row.city) if value
                ) or "Any",
                "config": row.config_bundle.name,
                "target": row.target_count,
                "threshold": row.replenish_below,
                "available": row.available_count,
                "reserved": row.reserved_count,
                "active": row.active,
                "admin_url": admin_change("proxypooltarget", row.pk),
            },
            title="Proxy pools",
            description="Country inventory targets, availability and refill thresholds.",
            columns=[
                t("provider", "Provider"), t("country", "Country"),
                t("location", "Location"), t("config", "Config"),
                t("target", "Target"), t("threshold", "Refill below"),
                t("available", "Available"), t("reserved", "Reserved"),
                s("active", "Active"),
            ],
            admin_url=reverse("admin:control_proxypooltarget_changelist"),
        )

    if resource == "proxy-inventory":
        queryset = ProxyPoolEntry.objects.select_related("target", "reserved_client")
        if query:
            queryset = queryset.filter(
                Q(target__provider_code__icontains=query)
                | Q(target__country_code__icontains=query)
                | Q(exit_ip__icontains=query)
                | Q(reserved_client__name__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "provider": row.target.provider_code,
                "country": row.target.country_code,
                "state": row.state,
                "exit_ip": str(row.exit_ip or ""),
                "score": row.fraud_score if row.fraud_score is not None else "",
                "device": row.reserved_client.name if row.reserved_client else "",
                "tested_at": iso(row.tested_at),
                "reserved_at": iso(row.reserved_at),
                "admin_url": admin_change("proxypoolentry", row.pk),
            },
            title="Proxy inventory",
            description="Pool state, exit IP quality and reservation ownership.",
            columns=[
                t("provider", "Provider"), t("country", "Country"),
                s("state", "State"), t("exit_ip", "Exit IP"),
                t("score", "Score"), t("device", "Reserved device"),
                d("tested_at", "Tested"), d("reserved_at", "Reserved"),
            ],
            admin_url=reverse("admin:control_proxypoolentry_changelist"),
        )

    if resource == "proxy-jobs":
        queryset = ProxyGenerationJob.objects.select_related("client")
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(status__icontains=query)
                | Q(error__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "id": row.pk,
                "device": row.client.name,
                "provider": row.provider_code,
                "country": row.country_code,
                "location": " / ".join(
                    value for value in (row.region, row.city) if value
                ) or "Any",
                "progress": f"{row.ready_count} / {row.requested_count}",
                "status": row.status,
                "error": row.error,
                "created_at": iso(row.created_at),
                "admin_url": admin_change("proxygenerationjob", row.pk),
            },
            title="Proxy generation jobs",
            description="Requested counts, progress and generation failures.",
            columns=[
                t("id", "Job"), t("device", "Device"),
                t("provider", "Provider"), t("country", "Country"),
                t("location", "Location"), t("progress", "Ready"),
                s("status", "Status"), t("error", "Error"),
                d("created_at", "Created"),
            ],
            admin_url=reverse("admin:control_proxygenerationjob_changelist"),
        )

    if resource == "reservations":
        queryset = ProxyReservation.objects.select_related("client", "job")
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(provider_code__icontains=query)
                | Q(country_code__icontains=query)
                | Q(profile_name__icontains=query)
                | Q(profile_id__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-reserved_at"),
            lambda row: {
                "id": row.pk,
                "device": row.client.name,
                "job": row.job_id or "",
                "provider": row.provider_code,
                "country": row.country_code,
                "profile_name": row.profile_name,
                "profile_id": row.profile_id,
                "reserved_at": iso(row.reserved_at),
                "admin_url": admin_change("proxyreservation", row.pk),
            },
            title="Proxy reservations",
            description="Unique proxy assignments linked to profile creation.",
            columns=[
                t("id", "Reservation"), t("device", "Device"),
                t("job", "Job"), t("provider", "Provider"),
                t("country", "Country"), t("profile_name", "Profile"),
                t("profile_id", "Profile ID"), d("reserved_at", "Reserved"),
            ],
            admin_url=reverse("admin:control_proxyreservation_changelist"),
        )

    if resource == "profile-activity":
        queryset = ProfileActivity.objects.select_related(
            "client", "job", "reservation"
        )
        if query:
            queryset = queryset.filter(
                Q(client__name__icontains=query)
                | Q(client__device_id__icontains=query)
                | Q(profile_name__icontains=query)
                | Q(profile_id__icontains=query)
                | Q(group_id__icontains=query)
                | Q(status__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "created_at": iso(row.created_at),
                "device": row.client.name,
                "office": row.client.office_name,
                "group_id": row.group_id,
                "profile_name": row.profile_name,
                "profile_id": row.profile_id,
                "status": row.status,
                "job": row.job_id or "",
                "reservation": row.reservation_id or "",
                "admin_url": admin_change("profileactivity", row.pk),
            },
            title="Profile activity",
            description="Profile request, reservation and open lifecycle events.",
            columns=[
                d("created_at", "Time"), t("device", "Device"),
                t("office", "Office"), t("group_id", "Group"),
                t("profile_name", "Profile"), t("profile_id", "Profile ID"),
                s("status", "Status"), t("job", "Job"),
                t("reservation", "Reservation"),
            ],
            admin_url=reverse("admin:control_profileactivity_changelist"),
        )

    if resource == "access-audit":
        queryset = BootstrapAudit.objects.select_related("client")
        if query:
            queryset = queryset.filter(
                Q(observed_ip__icontains=query)
                | Q(reported_ip__icontains=query)
                | Q(device_id__icontains=query)
                | Q(client__name__icontains=query)
                | Q(reason__icontains=query)
            )
        return _resource_page(
            request,
            queryset.order_by("-created_at"),
            lambda row: {
                "created_at": iso(row.created_at),
                "client": row.client.name if row.client else "Unknown",
                "observed_ip": str(row.observed_ip or ""),
                "reported_ip": str(row.reported_ip or ""),
                "device_id": row.device_id,
                "allowed": row.allowed,
                "reason": row.reason,
                "version": row.app_version,
                "admin_url": admin_change("bootstrapaudit", row.pk),
            },
            title="Access audit",
            description="Bootstrap authorization decisions with IP and device evidence.",
            columns=[
                d("created_at", "Time"), t("client", "Client"),
                t("observed_ip", "Observed IP"), t("reported_ip", "Reported IP"),
                t("device_id", "Device ID"), s("allowed", "Allowed"),
                t("reason", "Reason"), t("version", "App version"),
            ],
            admin_url=reverse("admin:control_bootstrapaudit_changelist"),
        )

    return panel_json({"message": "Unknown panel resource."}, status=404)
