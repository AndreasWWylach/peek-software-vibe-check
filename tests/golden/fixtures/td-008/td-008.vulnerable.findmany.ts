import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function listProjects() {
  // ❌ FLAW: no tenant scope — returns every tenant's projects
  return prisma.project.findMany({ where: { status: 'active' } });
}
