// HARDENED (Express) — tier derived from the provider-verified subscription id.
import express from 'express';

const app = express();

app.post('/api/subscribe', async (req, res) => {
  const realTier = await deriveTierFromSubscription(req.body.subscriptionID);
  if (!realTier) {
    res.status(400).json({ error: 'unknown subscription' });
    return;
  }
  await db.users.update({ billingTier: realTier });
  res.json({ ok: true });
});
