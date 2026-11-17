// Golden fixture: a pilot/CLI script that drives the Firebase Auth REST API
// (identitytoolkit.googleapis.com) directly. The `key` query parameter is the
// public Firebase web apiKey — the same key the browser bundle ships. The key
// is a fake, high-entropy AIzaSy value that Gitleaks flags.
import { initializeApp, cert } from 'firebase-admin/app';

initializeApp({ credential: cert(process.env.SA), projectId: 'example-app' });

const API_KEY = 'AIzaSyQFwAfGoCsheReohWSvhShgW7mOhIlMQGa'; // the public web app key

const r = await fetch(
  `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`,
  { method: 'POST' },
);
