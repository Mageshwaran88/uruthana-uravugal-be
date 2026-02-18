import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { OtpPurpose, OtpChannel } from './otp.enums';
import { generateOtp, hashOtp } from '../../common/utils/hash.util';

const OTP_EXPIRY_MINUTES = 10;
const OTP_LENGTH = 6;

function isEmail(identifier: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
}

/** Typed access to OtpVerification delegate (avoids Prisma client type resolution issues). */
interface OtpVerificationDelegate {
  deleteMany: (args?: { where?: unknown }) => Promise<unknown>;
  create: (args: { data: unknown }) => Promise<unknown>;
  findFirst: (args?: { where?: unknown }) => Promise<unknown>;
  update: (args: { where: { id: string }; data: unknown }) => Promise<unknown>;
}

@Injectable()
export class OtpService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
  ) {}

  private get otpVerification(): OtpVerificationDelegate {
    return (this.prisma as unknown as { otpVerification: OtpVerificationDelegate }).otpVerification;
  }

  async createAndSend(
    identifier: string,
    purpose: OtpPurpose,
    channel: OtpChannel,
  ): Promise<{ message: string }> {
    const normalized = identifier.trim().toLowerCase();
    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await this.otpVerification.deleteMany({
      where: { identifier: normalized, purpose },
    });

    await this.otpVerification.create({
      data: {
        identifier: normalized,
        otpHash,
        channel,
        purpose,
        expiresAt,
      },
    });

    if (channel === OtpChannel.EMAIL) {
      await this.sendEmailOtp(normalized, otp, purpose);
    } else {
      await this.sendSmsOtp(normalized, otp, purpose);
    }

    return {
      message:
        channel === OtpChannel.EMAIL
          ? 'If this email is registered, you will receive an OTP shortly.'
          : 'If this number is registered, you will receive an OTP shortly.',
    };
  }

  private async sendEmailOtp(
    email: string,
    otp: string,
    purpose: OtpPurpose,
  ): Promise<void> {
    const host = this.config.get<string>('smtp.host');
    const user = this.config.get<string>('smtp.user');
    const pass = this.config.get<string>('smtp.pass');
    if (!host || !user || !pass) {
      console.warn(
        `[OTP] Email not sent: SMTP not configured (host=${!!host}, user=${!!user}, pass=${!!pass}). OTP for ${email}: ${otp}`,
      );
      return;
    }
    try {
      const nodemailer = await import('nodemailer');
      const transporter = nodemailer.createTransport({
        host,
        port: this.config.get<number>('smtp.port', 587),
        secure: this.config.get('smtp.secure', false),
        auth: { user, pass },
      });
      const from = this.config.get<string>('smtp.from', user);
      const subject =
        purpose === OtpPurpose.REGISTER
          ? 'Your registration OTP'
          : 'Reset your password - OTP';
      await transporter.sendMail({
        from,
        to: email,
        subject,
        text: `Your OTP is: ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes.`,
        html: `<p>Your OTP is: <strong>${otp}</strong></p><p>It expires in ${OTP_EXPIRY_MINUTES} minutes.</p>`,
      });
    } catch (err: unknown) {
      const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : undefined;
      if (code === 'EAUTH' && host?.includes('gmail')) {
        console.error(
          '[OTP] Gmail SMTP auth failed. Use an App Password, not your normal password: ' +
          'Google Account → Security → 2-Step Verification → App passwords. Set SMTP_PASS in .env to the 16-character app password.',
        );
      } else {
        console.error('[OTP] Send email failed:', err);
      }
      console.warn(`[OTP] Fallback - ${purpose} for ${email}: ${otp}`);
    }
  }

  private async sendSmsOtp(
    mobile: string,
    otp: string,
    _purpose: OtpPurpose,
  ): Promise<void> {
    const apiUrl = this.config.get<string>('sms.apiUrl');
    const apiKey = this.config.get<string>('sms.apiKey');
    if (!apiUrl || !apiKey) {
      console.warn(
        `[OTP] SMS not sent: API not configured (apiUrl=${!!apiUrl}, apiKey=${!!apiKey}). OTP for ${mobile}: ${otp}`,
      );
      return;
    }
    const numbers = mobile.replace(/\D/g, '').slice(-10);
    if (numbers.length < 10) {
      console.warn(`[OTP] SMS skipped: invalid number ${mobile}. OTP: ${otp}`);
      return;
    }
    try {
      // Fast2SMS bulkV2 OTP format: https://www.fast2sms.com/dev/bulkV2
      const body: Record<string, string> = {
        route: 'otp',
        numbers,
        variables_values: otp,
        flash: '0',
      };
      const senderId = this.config.get<string>('sms.senderId');
      if (senderId) body.sender_id = senderId;
      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          authorization: apiKey,
        },
        body: JSON.stringify(body),
      });
      const text = await res.text();
      if (!res.ok) {
        console.warn('[OTP] SMS API error:', res.status, text);
        console.warn(`[OTP] Fallback for ${mobile}: ${otp}`);
        return;
      }
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
      const ok = json && typeof json === 'object' && 'return' in json && (json as { return?: boolean }).return === true;
      if (!ok) {
        console.warn('[OTP] SMS API returned failure:', json);
        console.warn(`[OTP] Fallback for ${mobile}: ${otp}`);
      }
    } catch (err) {
      console.error('[OTP] Send SMS failed:', err);
      console.warn(`[OTP] Fallback for ${mobile}: ${otp}`);
    }
  }

  async verify(
    identifier: string,
    purpose: OtpPurpose,
    otp: string,
  ): Promise<boolean> {
    const normalized = identifier.trim().toLowerCase();
    const record = (await this.otpVerification.findFirst({
      where: {
        identifier: normalized,
        purpose,
        expiresAt: { gt: new Date() },
        usedAt: null,
      },
    })) as { id: string; otpHash: string } | null;
    if (!record) return false;
    const hash = hashOtp(otp);
    if (hash !== record.otpHash) return false;
    await this.otpVerification.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });
    return true;
  }

  static getChannel(identifier: string): OtpChannel {
    return isEmail(identifier) ? OtpChannel.EMAIL : OtpChannel.SMS;
  }
}
