// Golden fixture: open-redirect hygiene rules must stay silent on safe patterns.
function login(req, res) {
  res.redirect('/home');
  res.redirect(302, '/dashboard');
}
