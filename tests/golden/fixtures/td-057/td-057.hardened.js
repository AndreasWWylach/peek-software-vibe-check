// OWN api with a literal host — the route param is path data, not the destination.
export async function getUser(req, res) {
  const data = await fetch(`https://api.example.com/users/${req.params.id}`);
  res.send(await data.json());
}

// Request URL goes through an allowlist before any fetch.
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);
export async function preview(req, res) {
  const url = new URL(req.body.callbackUrl);
  if (!ALLOWED_HOSTS.has(url.hostname)) return res.status(400).end();
  const page = await axios.get(url.toString());
  res.json(page.data);
}

export async function status() {
  const data = await fetch('https://api.example.com/status');
  return data.json();
}
