// ❌ FLAW: hardcoded fallback ships a dev secret into production.
const jwtSecret = process.env.JWT_SECRET || 'super-secret-dev-key';
