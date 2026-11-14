// VULNERABLE — entitlement written straight from the client's claim (setdots S2 class).
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

export const activateSubscription = functions.https.onCall(async (data, context) => {
  await admin.firestore().collection('users').doc(context.auth.uid).set(
    { billingTier: data.tier, isActive: true },
    { merge: true },
  );
  return { ok: true };
});
