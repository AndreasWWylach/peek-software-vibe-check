export async function handleWebhook(event: any): Promise<void> {
  // @ts-ignore
  const order = await db.orders.find(event.data.object.metadata.order_id);
  // @ts-ignore
  await db.orders.update(order.id, { status: 'paid' });
}
