import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// GET /api/news — a global catalog model with NO tenant column by design.
// It must never fire TD-008, even though its query omits any tenant filter.
router.get('/news', async (_req: any, res: Response) => {
  const articles = await prisma.newsArticle.findMany({ where: { isPublished: true } });
  return res.json({ articles });
});

export default router;
