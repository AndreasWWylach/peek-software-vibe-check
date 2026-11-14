// Stripe webhook (Express) — VULNERABLE: event read straight from the body, no signature verification.
import express from 'express';
import { activateSubscription } from './billing';

const app = express();

app.post('/webhooks/stripe', async (req, res) => {
  const event = req.body;
  if (event.type === 'checkout.session.completed') {
    await activateSubscription(event.data.object.customer);
  }
  res.json({ received: true });
});
