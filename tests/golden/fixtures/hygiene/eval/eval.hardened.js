// Golden fixture: eval hygiene rules must stay silent on explicit logic.
function double(a) {
  return a * 2;
}
const sum = 2 + 2;
