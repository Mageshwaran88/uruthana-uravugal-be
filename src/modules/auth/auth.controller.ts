import {
  Body,
  Controller,
  Get,
  Post,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ResetPasswordWithOtpDto } from './dto/reset-password-with-otp.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { JwtRefreshGuard } from '../../common/guards/jwt-refresh.guard';
import { CurrentUser, CurrentUserPayload } from '../../common/decorators/current-user.decorator';
import { Public } from '../../common/decorators/public.decorator';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private auth: AuthService,
    private config: ConfigService,
  ) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const result = await this.auth.login(dto);
    this.setRefreshCookie(res, result);
    return {
      success: true,
      user: result.user,
      token: result.accessToken,
      expiresIn: result.expiresIn,
    };
  }

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register new user' })
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.register(dto);
    this.setRefreshCookie(res, result);
    return {
      success: true,
      user: result.user,
      token: result.accessToken,
      expiresIn: result.expiresIn,
    };
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  async refresh(
    @CurrentUser() user: CurrentUserPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.refresh(user);
    this.setRefreshCookie(res, result);
    return {
      success: true,
      user: result.user,
      token: result.accessToken,
      expiresIn: result.expiresIn,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout and invalidate refresh token' })
  async logout(
    @CurrentUser() user: CurrentUserPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.auth.logout(user.id);
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: this.config.get('env') === 'production',
      sameSite: 'lax',
      path: '/',
    });
    return { success: true, message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user' })
  async me(@CurrentUser() user: CurrentUserPayload) {
    return this.auth.me(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password (requires current password)' })
  async changePassword(
    @CurrentUser() user: CurrentUserPayload,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.auth.changePassword(user.id, dto);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request OTP for password reset (email or mobile)' })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.auth.forgotPassword(dto);
  }

  @Public()
  @Post('send-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send OTP to email or mobile (REGISTER or FORGOT_PASSWORD)' })
  async sendOtp(@Body() dto: SendOtpDto) {
    return this.auth.sendOtp(dto.identifier, dto.purpose, dto.channel);
  }

  @Public()
  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify OTP' })
  async verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.auth.verifyOtp(dto.identifier, dto.purpose, dto.otp);
  }

  @Public()
  @Post('reset-password-with-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using OTP (no link)' })
  async resetPasswordWithOtp(@Body() dto: ResetPasswordWithOtpDto) {
    return this.auth.resetPasswordWithOtp(dto);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password with token from email link (legacy)' })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.auth.resetPassword(dto);
  }

  private setRefreshCookie(res: Response, result: { refreshToken: string }) {
    const expiresSec = this.config.get<number>('jwt.refreshExpiresSec', 604800);
    res.cookie('refresh_token', result.refreshToken, {
      httpOnly: true,
      secure: this.config.get('env') === 'production',
      sameSite: 'lax',
      maxAge: expiresSec * 1000,
      path: '/',
    });
  }
}
