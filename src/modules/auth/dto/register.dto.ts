import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength, Length, Matches } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

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

  @ApiPropertyOptional({ example: 'johndoe', description: 'Display name (optional)' })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional({ example: '+919876543210', description: 'Mobile number (optional)' })
  @IsOptional()
  @IsString()
  @Matches(/^[+]?[\d\s-]{10,20}$/, { message: 'Enter a valid mobile number' })
  mobile?: string;
}
