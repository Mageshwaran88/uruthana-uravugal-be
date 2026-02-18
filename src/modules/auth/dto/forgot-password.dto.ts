import { IsEmail, IsNotEmpty, IsOptional, IsString, ValidateIf } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({ example: 'user@example.com', required: false })
  @ValidateIf((o) => !o.mobile)
  @IsEmail()
  @IsNotEmpty({ message: 'Provide either email or mobile' })
  email?: string;

  @ApiProperty({ example: '+919876543210', required: false })
  @ValidateIf((o) => !o.email)
  @IsString()
  @IsNotEmpty({ message: 'Provide either email or mobile' })
  mobile?: string;
}
