// Stripe webhook (Express) — HARDENED: signature verified with constructEvent before anything runs.
import express from 'express';
import Stripe from 'stripe';
import { activateSubscription } from './billing';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);
const app = express();

app.post('/webhooks/stripe', async (req, res) => {
  const event = stripe.webhooks.constructEvent(
    req.rawBody,
    req.headers['stripe-signature'] as string,
    process.env.STRIPE_WEBHOOK_SECRET as string,
  );
  if (event.type === 'checkout.session.completed') {
    await activateSubscription(event.data.object.customer);
  }
  res.json({ received: true });
});
