import { onRequest } from 'firebase-functions/v2/https';

// Hardened: a request without the stripe-signature header is not Stripe —
// answer the expected 400 quietly (no signature-failure log, no security row).
// Only a present-but-wrong signature fails loudly.
export const stripeWebhook = onRequest(async (req, res) => {
  if (!isStripeDelivery(req.headers['stripe-signature'])) {
    res.sendStatus(400);
    return;
  }
  try {
    const event = constructEvent(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET!);
    await handle(event);
    res.sendStatus(200);
  } catch (err) {
    await recordSecurity('signature_failed');
    res.sendStatus(400);
  }
});

function isStripeDelivery(signatureHeader: string | string[] | undefined): boolean {
  const header = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
  return typeof header === 'string' && header.trim().length > 0;
}
async function handle(_event: unknown) { void _event; }
async function recordSecurity(_kind: string) { void _kind; }
function constructEvent(_body: unknown, _sig: unknown, _secret: unknown): unknown { return {}; }
