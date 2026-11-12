import { NextResponse } from 'next/server';
import Stripe from 'stripe';
import { z } from 'zod';

// Initialize Stripe securely on the server using environment variables
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
});

const checkoutSchema = z.object({
  amount: z.number().int().positive().max(1000000), // Enforce upper/lower limits in cents
});

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { amount } = checkoutSchema.parse(body);

    // ✅ HARDENED: PaymentIntent creation executed safely server-side
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      automatic_payment_methods: { enabled: true },
    });

    return NextResponse.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: 'Invalid checkout payload' }, { status: 400 });
    }
    console.error('[STRIPE_ERROR]', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
