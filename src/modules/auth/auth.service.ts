import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import { Role } from '@prisma/client';
import { hashPassword, verifyPassword, generateSecureToken } from '../../common/utils/hash.util';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ResetPasswordWithOtpDto } from './dto/reset-password-with-otp.dto';
import { RegisterWithPhoneDto } from './dto/register-with-phone.dto';
import { CurrentUserPayload } from '../../common/decorators/current-user.decorator';
import { OtpService } from './otp.service';
import { FirebaseService } from './firebase.service';
import { OtpChannel, OtpPurpose } from './otp.enums';
import * as crypto from 'crypto';

export interface AuthResponse {
  user: {
    id: string;
    name: string;
    email: string | null;
    mobile: string | null;
    role: string;
    avatarUrl: string | null;
  };
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
    private otp: OtpService,
    private firebase: FirebaseService,
  ) {}

  async login(dto: LoginDto): Promise<AuthResponse> {
    const identifier = dto.identifier.trim();
    const isEmail = identifier.includes('@');
    const user = await this.prisma.user.findFirst({
      where: {
        deletedAt: null,
        ...(isEmail
          ? { email: identifier.toLowerCase() }
          : { mobile: identifier }),
      },
    });
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid email/mobile or password');
    }
    const valid = await verifyPassword(user.passwordHash, dto.password);
    if (!valid) {
      throw new UnauthorizedException('Invalid email/mobile or password');
    }
    return this.issueTokens(user);
  }

  async register(dto: RegisterDto): Promise<AuthResponse> {
    const email = dto.email.trim().toLowerCase();
    const existing = await this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    });
    if (existing) {
      throw new ConflictException('Email already registered');
    }
    const verified = await this.otp.verify(email, OtpPurpose.REGISTER, dto.otp);
    if (!verified) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const passwordHash = await hashPassword(dto.password);
    const user = await this.prisma.user.create({
      data: {
        name: 'User',
        email,
        mobile: null,
        passwordHash,
        role: Role.USER,
        emailVerifiedAt: new Date(),
      },
    });
    return this.issueTokens(user);
  }

  async registerWithPhone(dto: RegisterWithPhoneDto): Promise<AuthResponse> {
    if (!this.firebase.isEnabled()) {
      throw new BadRequestException(
        'Firebase Phone Auth is not configured. Set FIREBASE_SERVICE_ACCOUNT_PATH in .env.',
      );
    }
    const decoded = await this.firebase.verifyIdToken(dto.firebaseIdToken);
    const phoneNumber = decoded.phone_number;
    if (!phoneNumber) {
      throw new BadRequestException('Invalid Firebase token: phone number not found');
    }
    const mobile = phoneNumber.replace(/\s/g, '').trim();
    const existing = await this.prisma.user.findFirst({
      where: { mobile, deletedAt: null },
    });
    if (existing) {
      throw new ConflictException('This mobile number is already registered');
    }
    const passwordHash = await hashPassword(dto.password);
    const user = await this.prisma.user.create({
      data: {
        name: 'User',
        email: null,
        mobile,
        passwordHash,
        role: Role.USER,
        mobileVerifiedAt: new Date(),
      },
    });
    return this.issueTokens(user);
  }

  async refresh(user: CurrentUserPayload): Promise<AuthResponse> {
    const full = await this.prisma.user.findFirst({
      where: { id: user.id, deletedAt: null },
    });
    if (!full) throw new UnauthorizedException('User not found');
    await this.prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    return this.issueTokens(full);
  }

  async logout(userId: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({ where: { userId } });
  }

  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });
    if (!user?.passwordHash) {
      throw new BadRequestException('Cannot change password for this account');
    }
    const valid = await verifyPassword(user.passwordHash, dto.currentPassword);
    if (!valid) {
      throw new UnauthorizedException('Current password is incorrect');
    }
    const newHash = await hashPassword(dto.newPassword);
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newHash },
      }),
      this.prisma.refreshToken.deleteMany({ where: { userId } }),
    ]);
    return { message: 'Password changed successfully. Please log in again.' };
  }

  async forgotPassword(dto: ForgotPasswordDto): Promise<{ message: string }> {
    const email = dto.email.trim().toLowerCase();
    const user = await this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    });
    if (!user) {
      return { message: 'If this account exists, you will receive an OTP shortly.' };
    }
    await this.otp.createAndSend(email, OtpPurpose.FORGOT_PASSWORD, OtpChannel.EMAIL);
    return { message: 'If this account exists, you will receive an OTP shortly.' };
  }

  async sendOtp(identifier: string, purpose: OtpPurpose, channel?: OtpChannel) {
    const normalized = identifier.trim().toLowerCase();

    // All OTP is sent by email only (no mobile/SMS)
    if (!normalized.includes('@')) {
      throw new BadRequestException('OTP is sent by email only. Enter your email address.');
    }

    if (purpose === OtpPurpose.REGISTER) {
      const existing = await this.prisma.user.findFirst({
        where: { email: normalized, deletedAt: null },
      });
      if (existing) {
        throw new ConflictException('Email already registered');
      }
      await this.otp.createAndSend(normalized, purpose, OtpChannel.EMAIL);
      return { message: 'OTP sent to your email.' };
    }

    if (purpose === OtpPurpose.FORGOT_PASSWORD) {
      const user = await this.prisma.user.findFirst({
        where: { email: normalized, deletedAt: null },
      });
      if (!user) {
        return { message: 'If this account exists, you will receive an OTP shortly.' };
      }
      await this.otp.createAndSend(normalized, purpose, OtpChannel.EMAIL);
      return { message: 'If this account exists, you will receive an OTP shortly.' };
    }

    await this.otp.createAndSend(normalized, purpose, OtpChannel.EMAIL);
    return { message: 'OTP sent to your email.' };
  }

  async verifyOtp(identifier: string, purpose: OtpPurpose, otp: string): Promise<{ valid: boolean }> {
    const valid = await this.otp.verify(identifier.trim().toLowerCase(), purpose, otp);
    return { valid };
  }

  async resetPasswordWithOtp(dto: ResetPasswordWithOtpDto): Promise<{ message: string }> {
    const normalized = dto.identifier.trim().toLowerCase();
    const valid = await this.otp.verify(normalized, OtpPurpose.FORGOT_PASSWORD, dto.otp);
    if (!valid) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const user = await this.prisma.user.findFirst({
      where: {
        deletedAt: null,
        OR: [{ email: normalized }, { mobile: dto.identifier.trim() }],
      },
    });
    if (!user) throw new BadRequestException('User not found');
    const newHash = await hashPassword(dto.newPassword);
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newHash },
      }),
      this.prisma.refreshToken.deleteMany({ where: { userId: user.id } }),
    ]);
    return { message: 'Password reset successfully. Please log in.' };
  }

  async resetPassword(dto: ResetPasswordDto): Promise<{ message: string }> {
    const tokenHash = crypto
      .createHash('sha256')
      .update(dto.token)
      .digest('hex');
    const record = await this.prisma.passwordResetToken.findFirst({
      where: {
        tokenHash,
        expiresAt: { gt: new Date() },
        usedAt: null,
      },
      include: { user: true },
    });
    if (!record) {
      throw new BadRequestException('Invalid or expired reset token');
    }
    const newHash = await hashPassword(dto.newPassword);
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { passwordHash: newHash },
      }),
      this.prisma.passwordResetToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      this.prisma.refreshToken.deleteMany({ where: { userId: record.userId } }),
    ]);
    return { message: 'Password reset successfully. Please log in.' };
  }

  async me(userId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        mobile: true,
        role: true,
        avatarUrl: true,
        emailVerifiedAt: true,
        createdAt: true,
      },
    });
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }

  private async issueTokens(user: {
    id: string;
    name: string;
    email: string | null;
    mobile?: string | null;
    role: Role;
    avatarUrl: string | null;
  }): Promise<AuthResponse> {
    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwt.sign(payload, {
      expiresIn: 900,
    });
    const refreshToken = this.jwt.sign(
      { sub: user.id, type: 'refresh' },
      {
        expiresIn: 604800,
      },
    );
    const expiresSec = this.config.get<number>(
      'jwt.refreshExpiresSec',
      7 * 24 * 60 * 60,
    );
    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + expiresSec * 1000),
      },
    });
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.mobile ?? null,
        role: user.role,
        avatarUrl: user.avatarUrl,
      },
      accessToken,
      refreshToken,
      expiresIn: 15 * 60,
    };
  }
}
