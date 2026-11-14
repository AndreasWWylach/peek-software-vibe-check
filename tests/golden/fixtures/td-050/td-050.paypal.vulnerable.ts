// PayPal webhook (Firebase Functions) — VULNERABLE: event read straight from the body, no verify-webhook-signature call.
import * as functions from 'firebase-functions';
import { admin } from './admin';

export const paypalWebhook = functions.https.onRequest(async (req, res) => {
  const event = req.body;
  if (event.event_type === 'BILLING.SUBSCRIPTION.ACTIVATED') {
    await admin.firestore().collection('users').doc(event.resource.id).update({ isActive: true });
  }
  res.status(200).send('OK');
});
