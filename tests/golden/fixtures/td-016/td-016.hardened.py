import os

import stripe

# ✅ HARDENED: secret read from the environment, never shipped in code.
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
