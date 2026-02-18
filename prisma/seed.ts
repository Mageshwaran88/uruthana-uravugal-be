import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

// Known passwords for seeded users (development only — never use in production)
const SEED_USERS = [
  { email: 'admin@example.com', name: 'Admin', password: 'admin123', role: 'ADMIN' as const },
  { email: 'test@example.com', name: 'Test User', password: 'test123', role: 'USER' as const },
];

async function main() {
  for (const u of SEED_USERS) {
    const hash = await argon2.hash(u.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
    });
    const user = await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: {
        email: u.email,
        name: u.name,
        passwordHash: hash,
        role: u.role,
        emailVerifiedAt: new Date(),
      },
    });
    console.log('Seeded:', user.email, `(password: ${u.password})`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
