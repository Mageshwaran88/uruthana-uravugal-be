/**
 * OTP enums matching Prisma schema.
 * Use these instead of @prisma/client to avoid depending on generated client for enums.
 */
export const OtpPurpose = {
  REGISTER: 'REGISTER',
  FORGOT_PASSWORD: 'FORGOT_PASSWORD',
} as const;

export type OtpPurpose = (typeof OtpPurpose)[keyof typeof OtpPurpose];

export const OtpChannel = {
  EMAIL: 'EMAIL',
  SMS: 'SMS',
} as const;

export type OtpChannel = (typeof OtpChannel)[keyof typeof OtpChannel];
