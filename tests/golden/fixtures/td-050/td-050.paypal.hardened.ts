// PayPal webhook (Firebase Functions) — HARDENED: signature verified against PayPal before the body is trusted.
import * as functions from 'firebase-functions';
import { admin } from './admin';

async function verifyWebhookSignature(headers: any, body: any): Promise<boolean> {
  const res = await fetch('https://api-m.paypal.com/v1/notifications/verify-webhook-signature', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.PAYPAL_ACCESS_TOKEN}` },
    body: JSON.stringify({
      auth_algo: headers['paypal-auth-algo'],
      cert_url: headers['paypal-cert-url'],
      transmission_id: headers['paypal-transmission-id'],
      transmission_sig: headers['paypal-transmission-sig'],
      transmission_time: headers['paypal-transmission-time'],
      webhook_id: process.env.PAYPAL_WEBHOOK_ID,
      webhook_event: body,
    }),
  });
  const data = await res.json();
  return data.verification_status === 'SUCCESS';
}

export const paypalWebhook = functions.https.onRequest(async (req, res) => {
  const valid = await verifyWebhookSignature(req.headers, req.body);
  if (!valid) {
    res.status(403).send('Signature verification failed');
    return;
  }
  const event = req.body;
  if (event.event_type === 'BILLING.SUBSCRIPTION.ACTIVATED') {
    await admin.firestore().collection('users').doc(event.resource.id).update({ isActive: true });
  }
  res.status(200).send('OK');
});
