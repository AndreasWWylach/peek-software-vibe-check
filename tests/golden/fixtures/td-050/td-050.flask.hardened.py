# Stripe webhook (Flask) — HARDENED: construct_event verifies the signature on the raw body first.
import stripe
from flask import Flask, request

app = Flask(__name__)


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    event = stripe.Webhook.construct_event(
        request.data,
        request.headers["Stripe-Signature"],
        "whsec_...",
    )
    if event.get("type") == "checkout.session.completed":
        activate_subscription(event["data"]["object"]["customer"])
    return {"received": True}
