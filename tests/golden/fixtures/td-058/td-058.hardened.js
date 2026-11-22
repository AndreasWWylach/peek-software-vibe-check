const bcrypt = require('bcrypt');
const crypto = require('crypto');

export async function register(req, res) {
  const hash = await bcrypt.hash(req.body.password, 12);
  // A checksum over file content is not password hashing.
  const digest = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  res.json({ hash, digest });
}
