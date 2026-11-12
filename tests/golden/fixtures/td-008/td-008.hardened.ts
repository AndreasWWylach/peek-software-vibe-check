import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import type { AuthenticatedRequest } from '../types/auth';

const router = Router();
const prisma = new PrismaClient();

const updateSettingsSchema = z.object({
  params: z.object({ projectId: z.string().uuid() }),
  body: z.object({
    name: z.string().min(1).max(100).optional(),
    theme: z.enum(['light', 'dark', 'system']).optional(),
    features: z.record(z.boolean()).optional(),
  }),
});

// PUT /api/projects/:projectId/settings
router.put('/projects/:projectId/settings', async (req: AuthenticatedRequest, res: Response) => {
  try {
    // 1. Require authenticated tenant context.
    if (!req.user?.organizationId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // 2. Validate the request.
    const { params, body } = updateSettingsSchema.parse({ params: req.params, body: req.body });

    // 3. Tenant-scoped update — the ID AND organization must both match.
    const updatedProject = await prisma.project.update({
      where: {
        id_organizationId: { id: params.projectId, organizationId: req.user.organizationId },
      },
      data: {
        ...(body.name && { name: body.name }),
        settings: {
          update: {
            ...(body.theme && { theme: body.theme }),
            ...(body.features && { features: body.features }),
          },
        },
      },
    });

    return res.status(200).json({ success: true, data: updatedProject });
  } catch (error: unknown) {
    const code =
      typeof error === 'object' && error !== null && 'code' in error
        ? (error as { code: unknown }).code
        : undefined;

    // P2025 = not found — missing OR owned by another tenant (don't leak which).
    if (code === 'P2025') return res.status(404).json({ error: 'Project not found' });

    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Invalid input payload', details: error.issues });
    }

    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
