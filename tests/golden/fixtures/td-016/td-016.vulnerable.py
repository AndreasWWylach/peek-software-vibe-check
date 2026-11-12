import stripe

# ❌ FLAW: hardcoded secret key.
# NOTE: fake placeholder to avoid secret-scanning push protection.
stripe.api_key = "sk_live_FAKE_EXAMPLE_KEY"
