// Golden fixture: a high-entropy (but fake) secret that Gitleaks'
// generic-api-key rule flags. Deliberately NOT a real provider prefix
// (sk_/ghp_/AKIA), so it also avoids GitHub push protection and does not
// overlap Semgrep's TD-016 prefix regex.
export const apiKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4";
