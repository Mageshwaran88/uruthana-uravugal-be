import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 16;
const AUTH_TAG_LEN = 16;
const SALT = process.env.ENCRYPTION_SALT ?? 'uruthana-uravugal-salt';

function getKey(): Buffer {
  const secret = process.env.ENCRYPTION_SECRET ?? 'uruthana-default-secret-change-in-prod';
  return scryptSync(secret, SALT, KEY_LEN);
}

export function encryptAmount(value: number | string): string {
  const text = String(value);
  const key = getKey();
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted.toString('base64')}`;
}

export function decryptAmount(encrypted: string): string {
  const [ivB64, authTagB64, dataB64] = encrypted.split(':');
  if (!ivB64 || !authTagB64 || !dataB64) return '';
  const key = getKey();
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(dataB64, 'base64', 'utf8') + decipher.final('utf8');
}

export function isEncrypted(value: string): boolean {
  return typeof value === 'string' && value.includes(':') && value.split(':').length === 3;
}
