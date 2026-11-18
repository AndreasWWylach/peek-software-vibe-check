import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// GET /api/requests/:id — ✅ scoped to the tenant (clientId) on a tenant-owned model.
router.get('/requests/:id', async (req: any, res: Response) => {
  const { id } = req.params;
  const clientId = req.user?.clientId;
  if (!clientId) return res.status(401).json({ error: 'Unauthorized' });
  const requestLog = await prisma.requestLog.findUnique({ where: { id, clientId } });
  return res.json({ requestLog });
});

export default router;
