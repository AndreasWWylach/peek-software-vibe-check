// Golden fixture: XSS hygiene rules must stay silent on safe patterns.
function renderProfile(user) {
  document.getElementById('profile').textContent = user.bio;
}

function Good({ html }) {
  return <div>{html}</div>;
}
