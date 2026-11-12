import { z } from 'zod';

const WebhookEvent = z.object({
  data: z.object({
    object: z.object({
      id: z.string(),
      metadata: z.object({ order_id: z.string() }).nullable(),
    }),
  }),
});

export async function handleWebhook(raw: unknown): Promise<void> {
  const event = WebhookEvent.parse(raw); // throws on any shape mismatch
  const orderId = event.data.object.metadata?.order_id;
  if (!orderId) return; // handle missing metadata explicitly
  await db.orders.update(orderId, { status: 'paid' });
}
