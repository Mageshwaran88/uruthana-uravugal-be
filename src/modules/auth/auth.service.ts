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
import { CurrentUserPayload } from '../../common/decorators/current-user.decorator';
import { OtpService } from './otp.service';
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
  ) {}

  async login(dto: LoginDto): Promise<AuthResponse> {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email.toLowerCase(),
        deletedAt: null,
      },
    });
    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid email or password');
    }
    const valid = await verifyPassword(user.passwordHash, dto.password);
    if (!valid) {
      throw new UnauthorizedException('Invalid email or password');
    }
    return this.issueTokens(user);
  }

  async register(dto: RegisterDto): Promise<AuthResponse> {
    const email = dto.email.toLowerCase().trim();
    const mobile = dto.mobile?.trim() || null;
    if (!mobile) {
      throw new BadRequestException('Mobile number is required for registration');
    }
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, { mobile: dto.mobile }],
        deletedAt: null,
      },
    });
    if (existing) {
      throw new ConflictException(
        existing.email === email ? 'Email already registered' : 'Mobile already registered',
      );
    }
    if (!dto.otp) {
      throw new BadRequestException('OTP is required. Request OTP first.');
    }
    const verified =
      (await this.otp.verify(email, OtpPurpose.REGISTER, dto.otp)) ||
      (await this.otp.verify(mobile, OtpPurpose.REGISTER, dto.otp));
    if (!verified) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const passwordHash = await hashPassword(dto.password);
    const role: Role = email === 'admin@example.com' ? Role.ADMIN : Role.USER;
    const user = await this.prisma.user.create({
      data: {
        name: dto.name.trim(),
        email,
        mobile,
        passwordHash,
        role,
        emailVerifiedAt: new Date(),
        mobileVerifiedAt: dto.otp ? new Date() : null,
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
    const email = dto.email?.trim().toLowerCase();
    const mobile = dto.mobile?.trim();
    if (!email && !mobile) {
      throw new BadRequestException('Provide either email or mobile');
    }
    const user = await this.prisma.user.findFirst({
      where: {
        deletedAt: null,
        OR: [
          ...(email ? [{ email }] : []),
          ...(mobile ? [{ mobile }] : []),
        ],
      },
    });
    if (!user) {
      return { message: 'If this account exists, you will receive an OTP shortly.' };
    }
    const identifier = email ?? mobile!;
    const channel = OtpService.getChannel(identifier);
    await this.otp.createAndSend(identifier, OtpPurpose.FORGOT_PASSWORD, channel);
    return { message: 'If this account exists, you will receive an OTP shortly.' };
  }

  async sendOtp(identifier: string, purpose: OtpPurpose, channel?: OtpChannel) {
    const normalized = identifier.trim().toLowerCase();
    if (purpose === OtpPurpose.FORGOT_PASSWORD) {
      const user = await this.prisma.user.findFirst({
        where: {
          deletedAt: null,
          OR: [
            { email: normalized },
            { mobile: identifier.trim() },
          ],
        },
      });
      if (!user) {
        return { message: 'If this account exists, you will receive an OTP shortly.' };
      }
      const sendTo = normalized.includes('@') ? user.email! : user.mobile ?? user.email!;
      const sendChannel = OtpService.getChannel(sendTo ?? normalized);
      await this.otp.createAndSend(sendTo ?? normalized, purpose, channel ?? sendChannel);
      return { message: 'If this account exists, you will receive an OTP shortly.' };
    }
    const ch = channel ?? OtpService.getChannel(normalized);
    await this.otp.createAndSend(normalized, purpose, ch);
    return { message: 'OTP sent. Check your email or phone.' };
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
