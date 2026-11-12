import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// PUT /api/projects/:projectId/settings
router.put('/projects/:projectId/settings', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const { name, theme, features } = req.body;

    // ❌ FLAW: updates by id alone — no scoping to the authenticated tenant
    const updatedProject = await prisma.project.update({
      where: { id: projectId },
      data: {
        name,
        settings: { update: { theme, features } },
      },
    });

    return res.status(200).json({ success: true, data: updatedProject });
  } catch {
    return res.status(500).json({ error: 'Failed to update project settings' });
  }
});

export default router;
