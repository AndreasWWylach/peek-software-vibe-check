// TD-032 vulnerable: identity taken from the request body, not the session.
export async function updateProfile(req: any, res: any) {
  const userId = req.body.userId; // ← client-supplied identity
  await db.users.update({ where: { id: userId }, data: { email: req.body.email } });
  res.json({ ok: true });
}
