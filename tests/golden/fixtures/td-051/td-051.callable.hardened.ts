// HARDENED — tier derived server-side from the verified plan, never the client's word.
import * as functions from 'firebase-functions';
import * as admin from 'firebase-admin';

async function tierForPlan(planId: string): string | null {
  const plans: Record<string, string> = { 'P-INDIE': 'indie', 'P-STUDIO': 'studio' };
  return plans[planId] ?? null;
}

export const activateSubscription = functions.https.onCall(async (data, context) => {
  const sub = await getPayPalSubscription(data.subscriptionID);
  const realTier = tierForPlan(sub.plan_id);
  if (!realTier) throw new functions.https.HttpsError('failed-precondition', 'Unknown plan');

  await admin.firestore().collection('users').doc(context.auth.uid).set(
    { billingTier: realTier, isActive: true },
    { merge: true },
  );
  return { ok: true };
});
