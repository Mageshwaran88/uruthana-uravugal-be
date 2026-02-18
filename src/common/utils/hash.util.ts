import * as argon2 from 'argon2';
import { randomBytes, createHash } from 'crypto';

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
  });
}

export async function verifyPassword(
  hash: string,
  plain: string,
): Promise<boolean> {
  return argon2.verify(hash, plain);
}

export function generateSecureToken(): string {
  return randomBytes(32).toString('hex');
}

const OTP_DIGITS = 6;
export function generateOtp(): string {
  const max = 10 ** OTP_DIGITS;
  const n = randomBytes(4).readUInt32BE(0) % max;
  return String(n).padStart(OTP_DIGITS, '0');
}

export function hashOtp(otp: string): string {
  return createHash('sha256').update(otp).digest('hex');
}
