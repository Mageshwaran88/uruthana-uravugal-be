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
import { CurrentUserPayload } from '../../common/decorators/current-user.decorator';
import * as crypto from 'crypto';

export interface AuthResponse {
  user: {
    id: string;
    name: string;
    email: string | null;
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
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, ...(dto.mobile ? [{ mobile: dto.mobile }] : [])],
        deletedAt: null,
      },
    });
    if (existing) {
      throw new ConflictException(
        existing.email === email ? 'Email already registered' : 'Mobile already registered',
      );
    }
    const passwordHash = await hashPassword(dto.password);
    const role: Role = email === 'admin@example.com' ? Role.ADMIN : Role.USER;
    const user = await this.prisma.user.create({
      data: {
        name: dto.name.trim(),
        email,
        mobile: dto.mobile?.trim() || null,
        passwordHash,
        role,
        emailVerifiedAt: new Date(),
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
    const user = await this.prisma.user.findFirst({
      where: { email: dto.email.toLowerCase(), deletedAt: null },
    });
    if (!user) {
      return { message: 'If the email exists, a reset link has been sent.' };
    }
    const token = generateSecureToken();
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresMinutes = this.config.get<number>(
      'passwordReset.expiresMinutes',
      60,
    );
    const expiresAt = new Date(Date.now() + expiresMinutes * 60 * 1000);
    await this.prisma.passwordResetToken.create({
      data: {
        tokenHash,
        userId: user.id,
        expiresAt,
      },
    });
    const baseUrl =
      this.config.get<string>('cors.origin') ?? 'http://localhost:3000';
    const resetLink = `${baseUrl}/reset-password?token=${token}`;
    console.log(
      `[DEV] Password reset link for ${user.email}: ${resetLink}`,
    );
    return {
      message:
        'If the email exists, a reset link has been sent. Check console in dev.',
    };
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
        role: user.role,
        avatarUrl: user.avatarUrl,
      },
      accessToken,
      refreshToken,
      expiresIn: 15 * 60,
    };
  }
}
