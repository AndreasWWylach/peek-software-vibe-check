'use client';

import { useState } from 'react';

export default function CheckoutButton({ amount }: { amount: number }) {
  const [loading, setLoading] = useState(false);

  const handleCheckout = async () => {
    setLoading(true);
    try {
      // Call the server route — no secret ever reaches the browser.
      const res = await fetch('/api/create-payment-intent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Checkout failed');

      // Hand data.clientSecret to Stripe Elements to confirm the payment.
      // stripe.confirmPayment({ elements, clientSecret: data.clientSecret });
    } catch (err: unknown) {
      console.error('Checkout error:', err instanceof Error ? err.message : err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleCheckout}
      disabled={loading}
      className='px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50'
    >
      {loading ? 'Processing...' : `Pay $${amount / 100}`}
    </button>
  );
}
