from __future__ import annotations

from functools import wraps
from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.db.models import Count, Sum
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .models import MonitoredDomain, ProfileActivity, ProfileDomainActivity, SubAdminAccount


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


@subadmin_required
@require_GET
def subadmin_dashboard(request: HttpRequest) -> HttpResponse:
    now = timezone.now()
    since = now - timedelta(hours=24)
    profiles_opened = ProfileActivity.objects.filter(
        status="profile_opened", created_at__gte=since
    ).count()
    domain_activity = ProfileDomainActivity.objects.filter(
        last_visited_at__gte=since
    ).aggregate(visits=Sum("visit_count"), domains=Count("domain", distinct=True))
    suspicious = ProfileDomainActivity.objects.filter(
        domain__in=MonitoredDomain.objects.filter(active=True).values("domain"),
        last_visited_at__gte=since,
    ).count()
    account = request.subadmin_account
    return render(
        request,
        "control/subadmin_dashboard.html",
        {
            "account": account,
            "generated_at": now,
            "metrics": {
                "profiles_opened": profiles_opened,
                "domain_visits": domain_activity["visits"] or 0,
                "unique_domains": domain_activity["domains"] or 0,
                "suspicious": suspicious,
            },
        },
    )


@require_POST
def subadmin_logout(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("control:subadmin-login")