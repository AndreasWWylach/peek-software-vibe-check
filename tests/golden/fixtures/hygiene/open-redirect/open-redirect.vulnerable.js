// Golden fixture: open-redirect hygiene rules must fire on request-input redirects.
function login(req, res) {
  res.redirect(req.query.next);
  res.redirect(302, req.query.dest);
  res.location = req.query.return;
}
