from __future__ import annotations

import ipaddress
from datetime import timedelta
from functools import wraps

from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Prefetch
from django.db.models import Count, Sum
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .models import (
    ClientAccess,
    ClientAccessIP,
    MonitoredDomain,
    ProfileActivity,
    ProfileDomainActivity,
    SubAdminAccount,
    SubAdminDomainExclusion,
    SubAdminScopeExclusion,
)


def subadmin_required(view):
    """Allow only active accounts created as SubAdminAccount records."""
    @wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(
                request.get_full_path(),
                login_url=reverse("control:subadmin-login"),
            )
        account = SubAdminAccount.objects.filter(
            user=request.user, active=True
        ).select_related("user").first()
        if account is None:
            logout(request)
            return redirect(reverse("control:subadmin-login") + "?disabled=1")
        request.subadmin_account = account
        return view(request, *args, **kwargs)

    return wrapped


def _safe_next(request: HttpRequest) -> str:
    candidate = str(request.POST.get("next") or request.GET.get("next") or "")
    if candidate and url_has_allowed_host_and_scheme(
        candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return candidate
    return reverse("control:subadmin-dashboard")


@require_http_methods(["GET", "POST"])
def subadmin_login(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated and SubAdminAccount.objects.filter(
        user=request.user, active=True
    ).exists():
        return redirect(_safe_next(request))

    error = ""
    if request.method == "POST":
        username = str(request.POST.get("username") or "").strip()
        password = str(request.POST.get("password") or "")
        user = authenticate(request, username=username, password=password)
        if user is not None and SubAdminAccount.objects.filter(
            user=user, active=True
        ).exists():
            login(request, user)
            SubAdminAccount.objects.filter(user=user).update(last_login_at=timezone.now())
            return redirect(_safe_next(request))
        error = "Invalid sub-admin credentials or inactive account."

    return render(
        request,
        "control/subadmin_login.html",
        {"error": error, "next": request.GET.get("next", "")},
    )


def _excluded_domains(account: SubAdminAccount) -> list[str]:
    return list(
        SubAdminDomainExclusion.objects.filter(account=account, active=True)
        .values_list("domain", flat=True)
    )


def _excluded_scopes(account: SubAdminAccount) -> dict[str, list[str]]:
    rows = SubAdminScopeExclusion.objects.filter(account=account, active=True)
    values = {"office": [], "group": []}
    for row in rows:
        values.setdefault(row.scope_type, []).append(row.value)
    return values


def _visible_domain_queryset(account: SubAdminAccount):
    queryset = ProfileDomainActivity.objects.select_related("client")
    excluded_domains = _excluded_domains(account)
    excluded_scopes = _excluded_scopes(account)
    if excluded_domains:
        queryset = queryset.exclude(domain__in=excluded_domains)
    if excluded_scopes["office"]:
        for value in excluded_scopes["office"]:
            queryset = queryset.exclude(client__office_name__iexact=value)
    if excluded_scopes["group"]:
        for value in excluded_scopes["group"]:
            queryset = queryset.exclude(group_id__iexact=value)
    return queryset


def _visible_profile_queryset(account: SubAdminAccount):
    queryset = ProfileActivity.objects.all()
    excluded_scopes = _excluded_scopes(account)
    if excluded_scopes["office"]:
        for value in excluded_scopes["office"]:
            queryset = queryset.exclude(client__office_name__iexact=value)
    if excluded_scopes["group"]:
        for value in excluded_scopes["group"]:
            queryset = queryset.exclude(group_id__iexact=value)
    return queryset

def _visible_client_queryset(account: SubAdminAccount):
    scopes = _excluded_scopes(account)
    queryset = ClientAccess.objects.select_related("config_bundle").prefetch_related(
        Prefetch("allowed_ips", to_attr="visible_allowed_ips")
    )
    for value in scopes["office"]:
        queryset = queryset.exclude(office_name__iexact=value)
    for value in scopes["group"]:
        queryset = queryset.exclude(config_bundle__browser_group_id__iexact=value)
    return queryset

def _activity_range(request: HttpRequest):
    now = timezone.now()
    selected = str(request.GET.get("range") or "7d").strip().lower()
    days = {"24h": 1, "7d": 7, "30d": 30}.get(selected, 7)
    return selected if selected in {"24h", "7d", "30d"} else "7d", now - timedelta(days=days), now


def _activity_rows(page):
    return [
        {
            "domain": row.domain,
            "visits": row.visit_count,
            "last_visited_at": row.last_visited_at,
            "profile_name": row.profile_name or row.profile_id,
            "profile_id": row.profile_id,
            "office_name": row.client.office_name,
            "system_number": row.client.system_number,
            "device_name": row.client.name,
            "device_id": row.client.device_id,
            "group_id": row.group_id,
        }
        for row in page.object_list
    ]


@subadmin_required
@require_GET
def subadmin_dashboard(request: HttpRequest) -> HttpResponse:
    now = timezone.now()
    since = now - timedelta(hours=24)
    visible_domains = _visible_domain_queryset(request.subadmin_account)
    domain_activity = visible_domains.filter(
        last_visited_at__gte=since
    ).aggregate(visits=Sum("visit_count"), domains=Count("domain", distinct=True))
    monitored = MonitoredDomain.objects.filter(active=True).values("domain")
    suspicious = visible_domains.filter(
        domain__in=monitored, last_visited_at__gte=since
    ).count()
    profiles_opened = _visible_profile_queryset(request.subadmin_account).filter(
        status="profile_opened", created_at__gte=since
    ).count()
    ip_clients = _visible_client_queryset(request.subadmin_account).order_by(
        "office_name", "system_number", "name"
    )
    ip_client_options = [
        {
            "id": client.pk,
            "office": client.office_name,
            "system": client.system_number,
            "name": client.name,
            "primary": str(client.ipv4),
            "additional": [
                str(item.ipv4)
                for item in client.visible_allowed_ips
                if item.active
            ],
        }
        for client in ip_clients
    ]
    return render(
        request,
        "control/subadmin_dashboard.html",
        {
            "account": request.subadmin_account,
            "generated_at": now,
            "metrics": {
                "profiles_opened": profiles_opened,
                "domain_visits": domain_activity["visits"] or 0,
                "unique_domains": domain_activity["domains"] or 0,
                "suspicious": suspicious,
            },
            "ip_client_options": ip_client_options,
            "active_page": "overview",
        },
    )


@subadmin_required
@require_GET
def subadmin_domain_activity(request: HttpRequest) -> HttpResponse:
    selected, start, end = _activity_range(request)
    queryset = _visible_domain_queryset(request.subadmin_account).filter(
        last_visited_at__gte=start, last_visited_at__lt=end
    )
    query = str(request.GET.get("q") or "").strip()
    office = str(request.GET.get("office") or "").strip()
    if query:
        queryset = queryset.filter(domain__icontains=query)
    if office:
        queryset = queryset.filter(client__office_name=office)
    aggregate = queryset.aggregate(
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        profiles=Count("profile_id", distinct=True),
    )
    page = Paginator(queryset.order_by("-last_visited_at", "domain"), 50).get_page(
        request.GET.get("page", 1)
    )
    offices = list(
        _visible_domain_queryset(request.subadmin_account)
        .exclude(client__office_name="")
        .values_list("client__office_name", flat=True)
        .distinct().order_by("client__office_name")
    )
    return render(
        request,
        "control/subadmin_activity.html",
        {
            "account": request.subadmin_account,
            "active_page": "domains",
            "kind": "domain",
            "title": "Domain activity",
            "description": "Visible profile browsing activity for your assigned workspace.",
            "selected_range": selected,
            "query": query,
            "office": office,
            "offices": offices,
            "metrics": {
                "visits": aggregate["visits"] or 0,
                "domains": aggregate["domains"] or 0,
                "profiles": aggregate["profiles"] or 0,
            },
            "rows": _activity_rows(page),
            "page": page,
        },
    )


@subadmin_required
@require_GET
def subadmin_suspicious_activity(request: HttpRequest) -> HttpResponse:
    selected, start, end = _activity_range(request)
    monitored = list(
        MonitoredDomain.objects.filter(active=True).values_list("domain", flat=True)
    )
    queryset = _visible_domain_queryset(request.subadmin_account).filter(
        domain__in=monitored, last_visited_at__gte=start, last_visited_at__lt=end
    )
    query = str(request.GET.get("q") or "").strip()
    if query:
        queryset = queryset.filter(domain__icontains=query)
    aggregate = queryset.aggregate(
        visits=Sum("visit_count"),
        domains=Count("domain", distinct=True),
        profiles=Count("profile_id", distinct=True),
    )
    page = Paginator(queryset.order_by("-last_visited_at", "domain"), 50).get_page(
        request.GET.get("page", 1)
    )
    return render(
        request,
        "control/subadmin_activity.html",
        {
            "account": request.subadmin_account,
            "active_page": "suspicious",
            "kind": "suspicious",
            "title": "Suspicious activity",
            "description": "Monitored domains accessed by visible profiles.",
            "selected_range": selected,
            "query": query,
            "office": "",
            "offices": [],
            "metrics": {
                "visits": aggregate["visits"] or 0,
                "domains": aggregate["domains"] or 0,
                "profiles": aggregate["profiles"] or 0,
            },
            "rows": _activity_rows(page),
            "page": page,
        },
    )


@subadmin_required
@require_http_methods(["GET", "POST"])
def subadmin_ip_access(request: HttpRequest) -> HttpResponse:
    account = request.subadmin_account
    clients = _visible_client_queryset(account).order_by(
        "office_name", "system_number", "name"
    )
    if request.method == "POST":
        client_id = str(request.POST.get("client_id") or "").strip()
        raw_ips = [str(value).strip() for value in request.POST.getlist("ipv4")]
        raw_ips = [value for value in raw_ips if value]
        client = clients.filter(pk=client_id).first()
        if client is None:
            messages.error(request, "That device is not available in your assigned offices/groups.")
        elif not raw_ips:
            messages.error(request, "Enter at least one IPv4 address.")
        else:
            parsed_ips = []
            invalid = None
            for raw_ip in raw_ips:
                try:
                    parsed = ipaddress.ip_address(raw_ip)
                    if not isinstance(parsed, ipaddress.IPv4Address):
                        raise ValueError
                    normalized = str(parsed)
                except ValueError:
                    invalid = raw_ip
                    break
                if normalized not in parsed_ips:
                    parsed_ips.append(normalized)
            if invalid:
                messages.error(request, f"{invalid} is not a valid IPv4 address.")
            elif len(parsed_ips) > 8:
                messages.error(request, "A device can have up to eight allowed IPv4 addresses.")
            else:
                try:
                    with transaction.atomic():
                        primary_ip = parsed_ips[0]
                        if primary_ip != str(client.ipv4):
                            if ClientAccess.objects.filter(
                                ipv4=primary_ip, device_id=client.device_id
                            ).exclude(pk=client.pk).exists():
                                raise ValueError("That IPv4 is already assigned to another device.")
                            client.ipv4 = primary_ip
                            client.save(update_fields=("ipv4", "updated_at"))

                        additional_ips = set(parsed_ips[1:])
                        ClientAccessIP.objects.filter(client=client).exclude(
                            ipv4__in=additional_ips
                        ).update(active=False)
                        for ip_value in additional_ips:
                            entry, _created = ClientAccessIP.objects.get_or_create(
                                client=client,
                                ipv4=ip_value,
                                defaults={"active": True},
                            )
                            entry.active = True
                            entry.full_clean()
                            entry.save(update_fields=("active",))
                except ValueError as exc:
                    messages.error(request, str(exc))
                else:
                    messages.success(
                        request,
                        f"Saved {len(parsed_ips)} allowed IP{'s' if len(parsed_ips) != 1 else ''} for {client.name}.",
                    )
        return redirect("control:subadmin-dashboard")

    return redirect("control:subadmin-dashboard")
@require_POST
def subadmin_logout(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("control:subadmin-login")