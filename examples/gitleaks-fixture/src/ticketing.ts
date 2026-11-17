// Golden fixture: a character-set (alphabet) constant. Gitleaks' generic-api-key
// rule flags these high-entropy-looking constants, but they are not secrets —
// they are the Crockford Base32 alphabet used to mint ticket tokens.
export const TOKEN_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const TOKEN_LENGTH = 20;
