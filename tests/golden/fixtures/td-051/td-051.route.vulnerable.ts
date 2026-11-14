// VULNERABLE (Express) — plan/price written from the request body.
import express from 'express';

const app = express();

app.post('/api/subscribe', async (req, res) => {
  await db.users.update({ billingTier: req.body.tier });
  res.json({ ok: true });
});
