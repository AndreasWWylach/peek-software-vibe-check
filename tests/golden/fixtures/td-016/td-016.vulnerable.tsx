'use client';

import { useState } from 'react';
import Stripe from 'stripe';

// ❌ FLAW: Instantiating Stripe client-side with a hardcoded Secret Key.
// NOTE: the real teardown key was replaced with a fake placeholder so this
// example fixture does not trip GitHub secret-scanning push protection.
const stripe = new Stripe('sk_live_FAKE_EXAMPLE_KEY', {
  apiVersion: '2023-10-16',
});

export default function CheckoutButton({ amount }: { amount: number }) {
  const [loading, setLoading] = useState(false);

  const handleCheckout = async () => {
    setLoading(true);
    try {
      // ❌ FLAW: Direct client-side invocation creating a PaymentIntent using secret privileges
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: 'usd',
        payment_method_types: ['card'],
      });

      if (paymentIntent.client_secret) {
        alert(`PaymentIntent Created! Secret: ${paymentIntent.client_secret}`);
      }
    } catch (err) {
      console.error('Checkout failed', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleCheckout}
      disabled={loading}
      className="px-4 py-2 bg-blue-600 text-white rounded"
    >
      {loading ? 'Processing...' : `Pay $${amount / 100}`}
    </button>
  );
}
