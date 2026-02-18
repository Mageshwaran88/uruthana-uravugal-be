import { IsEnum, IsNotEmpty, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OtpPurpose } from '../otp.enums';

export class VerifyOtpDto {
  @ApiProperty({ description: 'Email or mobile used when sending OTP' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ enum: ['REGISTER', 'FORGOT_PASSWORD'] })
  @IsEnum(OtpPurpose)
  purpose: OtpPurpose;

  @ApiProperty({ example: '123456', minLength: 6, maxLength: 6 })
  @IsString()
  @Length(6, 6)
  otp: string;
}
