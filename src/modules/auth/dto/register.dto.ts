import { IsEmail, IsNotEmpty, IsString, MinLength, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ example: 'user@example.com', description: 'Email (OTP sent to this email)' })
  @IsEmail()
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({ example: '123456', minLength: 6, maxLength: 6 })
  @IsString()
  @Length(6, 6, { message: 'OTP must be 6 digits' })
  @IsNotEmpty({ message: 'OTP is required. Request OTP first.' })
  otp: string;

  @ApiProperty({ example: 'password123', minLength: 6 })
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters' })
  @IsNotEmpty()
  password: string;
}
