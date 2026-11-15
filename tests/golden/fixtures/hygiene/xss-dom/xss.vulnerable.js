// Golden fixture: XSS hygiene rules must fire on these unconditionally-dangerous sinks.
function renderProfile(user) {
  document.write('<h1>' + user.name + '</h1>');
  document.getElementById('notes').insertAdjacentHTML('beforeend', user.html);
}
