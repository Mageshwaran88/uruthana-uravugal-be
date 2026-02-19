import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({ example: 'user@example.com', description: 'Email to receive OTP (forgot password uses email only)' })
  @IsEmail()
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
}
