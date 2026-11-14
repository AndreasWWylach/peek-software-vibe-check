# PayPal webhook (Django) — VULNERABLE: body parsed and acted on with no verify-webhook-signature call.
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def paypal_webhook(request):
    event = json.loads(request.body)
    if event.get("event_type") == "BILLING.SUBSCRIPTION.ACTIVATED":
        activate_user(event["resource"]["id"])
    return JsonResponse({"ok": True})
