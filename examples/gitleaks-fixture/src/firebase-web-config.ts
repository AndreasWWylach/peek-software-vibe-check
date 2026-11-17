// Golden fixture: a Firebase web SDK config object. The apiKey / App Check
// site key here are public by design — they ship in every browser bundle and
// the security boundary is Firestore rules + App Check, not key visibility.
// The apiKey is a fake, high-entropy AIzaSy value (not a real Firebase key) that
// Gitleaks' gcp-api-key rule actually flags, so the skip logic is exercised.
export const DEFAULT_FIREBASE_CONFIG = {
  apiKey: 'AIzaSyQFwAfGoCsheReohWSvhShgW7mOhIlMQGa',
  authDomain: 'example-app.firebaseapp.com',
  projectId: 'example-app',
  storageBucket: 'example-app.firebasestorage.app',
  messagingSenderId: '123456789012',
  appId: '1:123456789012:web:abc123def456',
};

export const DEFAULT_APP_CHECK_SITE_KEY = '6LcABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a';
