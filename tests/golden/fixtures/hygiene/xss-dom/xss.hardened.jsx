// Golden fixture: XSS hygiene rules must stay silent on safe patterns.
function renderProfile(user) {
  document.getElementById('profile').textContent = user.bio;
  document.getElementById('static').innerHTML = '<b>static</b>';
}

function Good({ html }) {
  return <div>{html}</div>;
}
