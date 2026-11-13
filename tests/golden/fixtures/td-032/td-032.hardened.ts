// TD-032 hardened: identity from the authenticated session.
export async function updateProfile(req: any, res: any) {
  const userId = req.session.userId; // ← session identity
  await db.users.update({ where: { id: userId }, data: { email: req.body.email } });
  res.json({ ok: true });
}
