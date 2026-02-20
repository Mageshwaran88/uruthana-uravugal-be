/**
 * Ensures Prisma CLI can see DATABASE_URL on platforms (e.g. Railway) that
 * inject env at runtime: write it to .env so `prisma migrate deploy` loads it.
 * Run before prisma migrate deploy in production start.
 */
const fs = require('fs');
const path = require('path');

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error('FATAL: DATABASE_URL is not set. Set it in Railway Variables (one line, no line breaks).');
  process.exit(1);
}

const envPath = path.join(__dirname, '..', '.env');
const line = 'DATABASE_URL=' + dbUrl.replace(/\r?\n/g, '') + '\n';
fs.writeFileSync(envPath, line, 'utf8');
