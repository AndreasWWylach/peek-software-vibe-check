# Stripe webhook (Flask) — VULNERABLE: event read from request.json, no signature verification.
from flask import Flask, request

app = Flask(__name__)


@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    event = request.json
    if event.get("type") == "checkout.session.completed":
        activate_subscription(event["data"]["object"]["customer"])
    return {"received": True}
