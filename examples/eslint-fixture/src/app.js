// Golden fixture: triggers two core ESLint rules for the QA hygiene provider.
export function linty() {
  const unused = 42; // no-unused-vars (warn)
  return 1;
  const dead = true; // no-unreachable (error)
}
