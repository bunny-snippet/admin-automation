"""Admin-only controls for the shared exit-IP reuse policy."""
import json

from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_http_methods

from .exit_ip_cooldown import cooldown_policy_payload, set_cooldown_policy
from .panel_views import panel_json


@staff_member_required
@require_http_methods(["GET", "POST"])
def proxy_cooldown_api(request):
    can_change = request.user.is_superuser
    if request.method == "POST":
        if not can_change:
            return panel_json({"ok": False, "message": "Only a full administrator can change the global IP cooldown."}, status=403)
        try:
            body = json.loads(request.body)
            if not isinstance(body, dict) or type(body.get("enabled")) is not bool:
                raise ValueError("enabled must be a boolean.")
            revision = body.get("expected_revision")
            if type(revision) is not int or revision < 0:
                raise ValueError("A valid policy revision is required. Refresh and try again.")
        except (ValueError, UnicodeDecodeError) as error:
            return panel_json({"ok": False, "message": str(error)}, status=400)
        try:
            policy = set_cooldown_policy(body["enabled"], actor=f"Warrior admin:{request.user.pk}:{request.user.get_username()}", expected_revision=revision)
        except ValueError as error:
            return panel_json({"ok": False, "message": str(error)}, status=409)
    else:
        policy = cooldown_policy_payload()
    return panel_json({"ok": True, "policy": policy, "can_change": can_change})
