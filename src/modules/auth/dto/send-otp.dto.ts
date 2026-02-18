import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OtpChannel, OtpPurpose } from '../otp.enums';  

export class SendOtpDto {
  @ApiProperty({ description: 'Email or mobile number' })
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
}
