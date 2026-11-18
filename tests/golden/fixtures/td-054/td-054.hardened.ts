// The failure is surfaced as a discriminated result, never a quiet zero.
export async function pendingCount(
  listAccessRequests: () => Promise<unknown[]>,
): Promise<{ ok: boolean; count: number; message?: string }> {
  try {
    const requests = await listAccessRequests();
    return { ok: true, count: requests.length };
  } catch (error) {
    return { ok: false, count: 0, message: error instanceof Error ? error.message : 'failed' };
  }
}
