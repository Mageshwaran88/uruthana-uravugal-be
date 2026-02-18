import { IsNotEmpty, IsString, MinLength, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordWithOtpDto {
  @ApiProperty({ description: 'Email or mobile used when requesting reset' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ example: '123456', minLength: 6, maxLength: 6 })
  @IsString()
  @Length(6, 6)
  otp: string;

  @ApiProperty({ example: 'newPassword456', minLength: 6 })
  @IsString()
  @MinLength(6, { message: 'New password must be at least 6 characters' })
  @IsNotEmpty()
  newPassword: string;
}
