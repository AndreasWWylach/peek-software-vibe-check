const crypto = require('crypto');

export async function register(req, res) {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  const digest = createHash('sha256').update(pwd).digest('hex');
  res.json({ hash, digest });
}
