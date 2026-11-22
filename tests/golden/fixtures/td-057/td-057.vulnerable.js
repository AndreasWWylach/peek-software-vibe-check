// SSRF: the server fetches a URL taken verbatim from the request.
export async function proxy(req, res) {
  const data = await fetch(req.query.url);
  res.send(await data.text());
}

export async function preview(request, response) {
  const page = await axios.get(request.body.callbackUrl);
  response.json(page.data);
}

export function mirror(req, res) {
  http.get(req.params.target, (stream) => stream.pipe(res));
}
