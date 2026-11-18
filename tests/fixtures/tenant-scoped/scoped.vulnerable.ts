import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// GET /api/requests/:id — ❌ no tenant scope on a tenant-owned model.
router.get('/requests/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const requestLog = await prisma.requestLog.findUnique({ where: { id } });
  return res.json({ requestLog });
});

export default router;
