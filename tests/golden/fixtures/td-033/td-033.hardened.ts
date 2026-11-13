// TD-033 hardened: value passed as a placeholder argument.
export async function getOrder(db: any, orderId: string) {
  const rows = await db.query("SELECT * FROM orders WHERE id = ?", [orderId]);
  return rows;
}
