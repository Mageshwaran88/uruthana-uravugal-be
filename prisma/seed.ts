import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  const adminHash = await argon2.hash('admin123', {
    type: argon2.argon2id,
    memoryCost: 65536,
  });
  const user = await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      email: 'admin@example.com',
      name: 'Admin',
      passwordHash: adminHash,
      role: 'ADMIN',
      emailVerifiedAt: new Date(),
    },
  });
  console.log('Seeded admin:', user.email);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
