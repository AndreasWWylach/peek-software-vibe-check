// A failure is swallowed into null, so a caller reads a "quiet zero" — the
// console showed "0 pending access requests" even when the callable refused.
export async function pendingCount(listAccessRequests: () => Promise<unknown[]>): Promise<number> {
  const requests = await listAccessRequests().catch(() => null);
  return requests?.length ?? 0;
}
