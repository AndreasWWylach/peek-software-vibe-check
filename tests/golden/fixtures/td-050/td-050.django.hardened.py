# PayPal webhook (Django) — HARDENED: signature verified before the body is trusted.
import json
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


def verify_webhook_signature(headers, body):
    res = requests.post(
        "https://api-m.paypal.com/v1/notifications/verify-webhook-signature",
        headers={"Content-Type": "application/json", "Authorization": "Bearer ..."},
        json={
            "auth_algo": headers.get("paypal-auth-algo"),
            "transmission_id": headers.get("paypal-transmission-id"),
            "transmission_sig": headers.get("paypal-transmission-sig"),
            "transmission_time": headers.get("paypal-transmission-time"),
            "cert_url": headers.get("paypal-cert-url"),
            "webhook_id": "WH-...",
            "webhook_event": json.loads(body),
        },
    )
    return res.json().get("verification_status") == "SUCCESS"


@csrf_exempt
def paypal_webhook(request):
    valid = verify_webhook_signature(request.headers, request.body)
    if not valid:
        return JsonResponse({"error": "bad signature"}, status=403)
    event = json.loads(request.body)
    if event.get("event_type") == "BILLING.SUBSCRIPTION.ACTIVATED":
        activate_user(event["resource"]["id"])
    return JsonResponse({"ok": True})
