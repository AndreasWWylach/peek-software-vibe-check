// Control — NOT a webhook: a plain route that reads req.body must stay silent.
import express from 'express';
import { updateProfile } from './profiles';

const app = express();

app.post('/api/profile', async (req, res) => {
  const { name } = req.body;
  await updateProfile(req.user.id, name);
  res.json({ ok: true });
});
