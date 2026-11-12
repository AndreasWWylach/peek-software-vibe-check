// ✅ HARDENED: fail fast — a missing secret crashes at startup, never silently falls back.
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error('JWT_SECRET is required');
}
