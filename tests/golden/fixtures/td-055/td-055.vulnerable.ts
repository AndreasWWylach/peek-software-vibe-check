import { onRequest } from 'firebase-functions/v2/https';

// Vulnerable: a request with NO stripe-signature header (an uptime probe's
// bare GET, a browser, a scanner) reaches constructEvent, which throws — and
// the catch logs a *failed signature* (alert + security row), every minute.
// "Absent header" is conflated with "wrong signature".
export const stripeWebhook = onRequest(async (req, res) => {
  try {
    const event = constructEvent(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET!);
    await handle(event);
    res.sendStatus(200);
  } catch (err) {
    await recordSecurity('signature_failed');
    res.sendStatus(400);
  }
});

async function handle(_event: unknown) { void _event; }
async function recordSecurity(_kind: string) { void _kind; }
function constructEvent(_body: unknown, _sig: unknown, _secret: unknown): unknown { return {}; }
