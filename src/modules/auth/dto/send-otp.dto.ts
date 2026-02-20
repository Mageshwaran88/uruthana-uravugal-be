import { IsEmail, IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OtpChannel, OtpPurpose } from '../otp.enums';

export class SendOtpDto {
  @ApiProperty({ description: 'Email or mobile number (account email)' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ enum: OtpPurpose })
  @IsEnum(OtpPurpose)
  purpose: OtpPurpose;

  @ApiProperty({ enum: OtpChannel, required: false })
  @IsOptional()
  @IsEnum(OtpChannel)
  channel?: OtpChannel;

  @ApiProperty({ description: 'Send OTP to this email instead (e.g. personal Gmail when Resend restricts recipient)', required: false })
  @IsOptional()
  @IsString()
  @IsEmail()
  sendOtpTo?: string;
}
