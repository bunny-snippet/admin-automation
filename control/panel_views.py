from __future__ import annotations

import csv
from datetime import datetime, time, timedelta
from typing import Any

from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q, Sum
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.views.decorators.http import require_GET

from .models import (
    BootstrapAudit,
    ClientAccess,
    ConfigBundle,
    ExtensionPackage,
    ProfileActivity,
    ProfileDomainActivity,
    MonitoredDomain,
    Provider,
    ProxyGenerationJob,
    ProxyPoolEntry,
)


def profile_display_name(row: Any) -> str:
    """Return the readable profile label used throughout the control panel."""
    candidates = (
        getattr(row, "profile_name", ""),
        getattr(getattr(row, "reservation", None), "profile_name", ""),
        getattr(getattr(row, "client", None), "profile_name", ""),
        getattr(getattr(row, "client", None), "name", ""),
        getattr(row, "profile_id", ""),
    )
    for value in candidates:
        value = str(value or "").strip()
        if value:
            return value
    return "Unnamed"

def panel_json(payload: dict[str, Any], status: int = 200) -> JsonResponse:
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def iso(value: datetime | None) -> str:
    if value is None:
        return ""
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.isoformat()


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, parsed))


def admin_change(model_name: str, object_id: int) -> str:
    return reverse(f"admin:control_{model_name}_change", args=(object_id,))


def domain_range(request: HttpRequest) -> tuple[datetime, datetime, str]:
    now = timezone.now()
    preset = str(request.GET.get("range") or "7d").strip().lower()
    preset_days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
    start = now - timedelta(days=preset_days.get(preset, 7))
    end = now
    from_value = str(request.GET.get("from") or "").strip()
    to_value = str(request.GET.get("to") or "").strip()
    if from_value:
        parsed = parse_datetime(from_value)
        if parsed is None:
            parsed_date = parse_date(from_value)
            if parsed_date is not None:
                parsed = datetime.combine(parsed_date, time.min)
        if parsed is not None:
            start = timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed
            preset = "custom"
    if to_value:
        parsed = parse_datetime(to_value)
        if parsed is None:
            parsed_date = parse_date(to_value)
            if parsed_date is not None:
                parsed = datetime.combine(parsed_date + timedelta(days=1), time.min)
        if parsed is not None:
            end = timezone.make_aware(parsed) if timezone.is_naive(parsed) else parsed
            preset = "custom"
    if start >= end:
        start = end - timedelta(days=7)
    return start, end, preset


def domain_queryset(request: HttpRequest):
    start, end, preset = domain_range(request)
    queryset = ProfileDomainActivity.objects.select_related(
        "client", "job", "reservation"
    ).filter(last_visited_at__gte=start, last_visited_at__lt=end)
    exact_filters = {
        "client_id": "client",
        "client__office_name": "office",
        "client__ipv4": "ip",
        "client__device_id": "device",
        "group_id": "group",
        "profile_id": "profile_id",
        "session_id": "session",
    }
    for field, parameter in exact_filters.items():
        value = str(request.GET.get(parameter) or "").strip()
        if value:
            queryset = queryset.filter(**{field: value})
    domain = str(request.GET.get("domain") or "").strip()
    if domain:
        queryset = queryset.filter(domain__icontains=domain)
    profile_name = str(request.GET.get("profile_name") or "").strip()
    if profile_name:
        queryset = queryset.filter(profile_name__icontains=profile_name)
    query = str(request.GET.get("q") or "").strip()
    if query:
        queryset = queryset.filter(
            Q(domain__icontains=query)
            | Q(client__name__icontains=query)
            | Q(client__office_name__icontains=query)
            | Q(client__device_id__icontains=query)
            | Q(client__ipv4__icontains=query)
            | Q(profile_name__icontains=query)
            | Q(profile_id__icontains=query)
            | Q(browser_id__icontains=query)
            | Q(session_id__icontains=query)
        )
    return queryset, start, end, preset


def domain_row(row: ProfileDomainActivity) -> dict[str, Any]:
    duration = max(
        0, int((row.session_ended_at - row.session_started_at).total_seconds())
    )
    return {
        "id": row.pk,
        "domain": row.domain,
        "visit_count": row.visit_count,
        "first_visited_at": iso(row.first_visited_at),
        "last_visited_at": iso(row.last_visited_at),
        "session_started_at": iso(row.session_started_at),
        "session_ended_at": iso(row.session_ended_at),
        "session_duration_seconds": duration,
        "session_id": row.session_id,
        "group_id": row.group_id,
        "profile_name": profile_display_name(row),
        "profile_id": row.profile_id,
        "browser_id": row.browser_id,
        "client_id": row.client_id,
        "client_name": row.client.name,
        "office_name": row.client.office_name,
        "system_number": row.client.system_number,
        "ipv4": str(row.client.ipv4),
        "device_id": row.client.device_id,
        "job_id": row.job_id,
        "reservation_id": row.reservation_id,
        "admin_url": admin_change("profiledomainactivity", row.pk),
    }


def suspicious_queryset(request: HttpRequest):
    queryset, start, end, preset = domain_queryset(request)
    monitored = list(
        MonitoredDomain.objects.filter(active=True).values_list("domain", flat=True)
    )
    return queryset.filter(domain__in=monitored), start, end, preset, monitored
@staff_member_required(login_url="admin:login")
@require_GET
def panel(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "control/panel.html",
        {
            "panel_title": "Automation Control Center",
            "admin_url": reverse("admin:index"),
            "logout_url": reverse("admin:logout"),
        },
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_overview_api(request: HttpRequest) -> JsonResponse:
    now = timezone.now()
    since = now - timedelta(hours=24)
    domain_recent = ProfileDomainActivity.objects.filter(last_visited_at__gte=since)
    domain_totals = domain_recent.aggregate(
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    job_status = {
        row["status"]: row["count"]
        for row in ProxyGenerationJob.objects.values("status").annotate(count=Count("id"))
    }
    pool_status = {
        row["state"]: row["count"]
        for row in ProxyPoolEntry.objects.values("state").annotate(count=Count("id"))
    }
    bootstrap_status = BootstrapAudit.objects.filter(created_at__gte=since).aggregate(
        total=Count("id"),
        allowed_count=Count("id", filter=Q(allowed=True)),
        denied_count=Count("id", filter=Q(allowed=False)),
    )
    recent_domains = [
        domain_row(row)
        for row in ProfileDomainActivity.objects.select_related(
            "client", "job", "reservation"
        ).order_by("-last_visited_at")[:8]
    ]
    monitored_domains = list(
        MonitoredDomain.objects.filter(active=True).values_list("domain", flat=True)
    )
    suspicious_recent = [
        domain_row(row)
        for row in ProfileDomainActivity.objects.select_related("client")
        .filter(domain__in=monitored_domains, last_visited_at__gte=since)
        .order_by("-last_visited_at")[:8]
    ]
    office_rows = ClientAccess.objects.values("office_name").annotate(
        devices=Count("id"),
        active_devices=Count("id", filter=Q(active=True)),
        last_seen=Max("last_seen_at"),
    ).order_by("office_name")
    offices = [
        {
            "office_name": row["office_name"],
            "devices": row["devices"],
            "active_devices": row["active_devices"],
            "last_seen_at": iso(row["last_seen"]),
        }
        for row in office_rows
    ]
    return panel_json(
        {
            "generated_at": iso(now),
            "cards": {
                "devices": ClientAccess.objects.count(),
                "active_devices": ClientAccess.objects.filter(active=True).count(),
                "online_24h": ClientAccess.objects.filter(
                    active=True, last_seen_at__gte=since
                ).count(),
                "profiles_opened_24h": ProfileActivity.objects.filter(
                    status="profile_opened", created_at__gte=since
                ).count(),
                "domain_visits_24h": domain_totals["visits"] or 0,
                "unique_domains_24h": domain_totals["domains"] or 0,
                "sessions_24h": domain_totals["sessions"] or 0,
                "available_proxies": pool_status.get("available", 0),
                "suspicious_activity_24h": ProfileDomainActivity.objects.filter(
                    domain__in=monitored_domains, last_visited_at__gte=since
                ).count(),
            },
            "job_status": job_status,
            "pool_status": pool_status,
            "bootstrap_status": {
                "total": bootstrap_status["total"],
                "allowed": bootstrap_status["allowed_count"],
                "denied": bootstrap_status["denied_count"],
            },
            "recent_domains": recent_domains,
            "suspicious_recent": suspicious_recent,
            "monitored_domains": monitored_domains,
            "offices": offices,
            "management": [
                {"key": "devices", "label": "Devices", "count": ClientAccess.objects.count(), "description": "Whitelisted systems and assignments"},
                {"key": "configurations", "label": "Config bundles", "count": ConfigBundle.objects.count(), "description": "Runtime configuration and groups"},
                {"key": "providers", "label": "Providers", "count": Provider.objects.count(), "description": "Providers and country catalogs"},
                {"key": "extensions", "label": "Extensions", "count": ExtensionPackage.objects.count(), "description": "Managed browser packages"},
            ],
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_suspicious_activity_api(request: HttpRequest) -> JsonResponse:
    queryset, start, end, preset, monitored = suspicious_queryset(request)
    aggregate = queryset.aggregate(
        records=Count("id"),
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        clients=Count("client_id", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    queryset = queryset.order_by("-last_visited_at", "-id")
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(
        bounded_int(request.GET.get("page"), 1, 1, 1000000)
    )
    return panel_json({
        "range": {"preset": preset, "from": iso(start), "to": iso(end)},
        "monitored_domains": monitored,
        "metrics": {
            key: aggregate[key] or 0
            for key in ("records", "visits", "domains", "clients", "profiles", "sessions")
        },
        "rows": [domain_row(row) for row in page.object_list],
        "pagination": {
            "page": page.number, "pages": paginator.num_pages,
            "page_size": page_size, "total": paginator.count,
            "has_previous": page.has_previous(), "has_next": page.has_next(),
        },
        "monitor_admin_url": reverse("admin:control_monitoreddomain_changelist"),
    })
@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_api(request: HttpRequest) -> JsonResponse:
    queryset, start, end, preset = domain_queryset(request)
    aggregate = queryset.aggregate(
        records=Count("id"),
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        clients=Count("client_id", distinct=True),
        profiles=Count("profile_id", distinct=True),
        sessions=Count("session_id", distinct=True),
    )
    local_now = timezone.localtime(timezone.now())
    day_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)
    opened_today_qs = ProfileActivity.objects.filter(
        status__icontains="open",
        created_at__gte=day_start,
        created_at__lt=day_end,
    )
    office = str(request.GET.get("office") or "").strip()
    client_id = str(request.GET.get("client") or "").strip()
    group = str(request.GET.get("group") or "").strip()
    if office:
        opened_today_qs = opened_today_qs.filter(client__office_name=office)
    if client_id:
        opened_today_qs = opened_today_qs.filter(client_id=client_id)
    if group:
        opened_today_qs = opened_today_qs.filter(group_id=group)
    opened_today = opened_today_qs.count()
    top_domains = queryset.values("domain").annotate(
        visits=Sum("visit_count"),
        sessions=Count("session_id", distinct=True),
        clients=Count("client_id", distinct=True),
        last_seen_at=Max("last_visited_at"),
    ).order_by("-visits", "domain")[:10]
    top_domain_rows = [
        {**row, "last_seen_at": iso(row["last_seen_at"])} for row in top_domains
    ]
    sort_map = {
        "last_seen": "-last_visited_at",
        "first_seen": "first_visited_at",
        "visits": "-visit_count",
        "domain": "domain",
        "device": "client__name",
    }
    sort = str(request.GET.get("sort") or "last_seen")
    queryset = queryset.order_by(sort_map.get(sort, "-last_visited_at"), "-id")
    page_size = bounded_int(request.GET.get("page_size"), 25, 10, 100)
    paginator = Paginator(queryset, page_size)
    page = paginator.get_page(bounded_int(request.GET.get("page"), 1, 1, 1000000))
    office_source = ClientAccess.objects.all()
    group_source = ProfileDomainActivity.objects.all()
    options = {
        "offices": list(
            office_source.exclude(office_name="")
            .values_list("office_name", flat=True)
            .distinct().order_by("office_name")[:200]
        ),
        "groups": list(
            group_source.exclude(group_id="")
            .values_list("group_id", flat=True)
            .distinct().order_by("group_id")[:200]
        ),
        "clients": [
            {
                "id": row.pk,
                "name": row.name,
                "office_name": row.office_name,
                "system_number": row.system_number,
                "ipv4": str(row.ipv4),
                "device_id": row.device_id,
            }
            for row in ClientAccess.objects.order_by(
                "office_name", "system_number", "name"
            )[:500]
        ],
    }
    return panel_json(
        {
            "range": {"preset": preset, "from": iso(start), "to": iso(end)},
            "metrics": {
                "records": aggregate["records"] or 0,
                "visits": aggregate["visits"] or 0,
                "unique_domains": aggregate["domains"] or 0,
                "devices": aggregate["clients"] or 0,
                "profiles": aggregate["profiles"] or 0,
                "profiles_opened_today": opened_today,
                "sessions": aggregate["sessions"] or 0,
            },
            "top_domains": top_domain_rows,
            "rows": [domain_row(row) for row in page.object_list],
            "pagination": {
                "page": page.number,
                "pages": paginator.num_pages,
                "page_size": page_size,
                "total": paginator.count,
                "has_previous": page.has_previous(),
                "has_next": page.has_next(),
            },
            "options": options,
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_detail_api(
    request: HttpRequest, activity_id: int
) -> JsonResponse:
    row = get_object_or_404(
        ProfileDomainActivity.objects.select_related("client", "job", "reservation"),
        pk=activity_id,
    )
    session_rows = ProfileDomainActivity.objects.filter(
        client_id=row.client_id,
        profile_id=row.profile_id,
        session_id=row.session_id,
    ).order_by("first_visited_at", "domain").values(
        "id", "domain", "visit_count", "first_visited_at", "last_visited_at"
    )
    return panel_json(
        {
            "activity": domain_row(row),
            "session_domains": [
                {
                    "id": item["id"],
                    "domain": item["domain"],
                    "visit_count": item["visit_count"],
                    "first_visited_at": iso(item["first_visited_at"]),
                    "last_visited_at": iso(item["last_visited_at"]),
                }
                for item in session_rows
            ],
        }
    )


@staff_member_required(login_url="admin:login")
@require_GET
def panel_domain_activity_export(request: HttpRequest) -> HttpResponse:
    queryset, start, end, _preset = domain_queryset(request)
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M")
    response["Content-Disposition"] = f'attachment; filename="domain-activity-{stamp}.csv"'
    writer = csv.writer(response)
    writer.writerow([
        "Domain", "Visits", "First visited", "Last visited", "Session started",
        "Session ended", "Office", "System", "Device name", "IPv4", "Device ID",
        "Group ID", "Profile name", "Profile ID", "Browser ID", "Session ID",
        "Job ID", "Reservation ID", "Range from", "Range to",
    ])
    for row in queryset.order_by("-last_visited_at").iterator(chunk_size=2000):
        writer.writerow([
            row.domain, row.visit_count, iso(row.first_visited_at),
            iso(row.last_visited_at), iso(row.session_started_at),
            iso(row.session_ended_at), row.client.office_name,
            row.client.system_number, row.client.name, row.client.ipv4,
            row.client.device_id, row.group_id, profile_display_name(row), row.profile_id,
            row.browser_id, row.session_id, row.job_id or "",
            row.reservation_id or "", iso(start), iso(end),
        ])
    return response
