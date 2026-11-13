// TD-033 vulnerable: SQL assembled by string concatenation.
export async function getOrder(db: any, orderId: string) {
  const rows = await db.query("SELECT * FROM orders WHERE id = " + orderId);
  return rows;
}
