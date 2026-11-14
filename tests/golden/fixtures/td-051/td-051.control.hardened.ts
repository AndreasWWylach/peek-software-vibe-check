// Control — a non-entitlement field from client data must stay silent.
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

export const updateProfile = functions.https.onCall(async (data, context) => {
  await admin.firestore().collection('users').doc(context.auth.uid).set(
    { displayName: data.name, bio: data.bio },
    { merge: true },
  );
  return { ok: true };
});
