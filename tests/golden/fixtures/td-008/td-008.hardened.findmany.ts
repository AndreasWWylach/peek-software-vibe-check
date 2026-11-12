import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function listProjects(organizationId: string) {
  // ✅ HARDENED: tenant-scoped filter
  return prisma.project.findMany({ where: { status: 'active', organizationId } });
}
