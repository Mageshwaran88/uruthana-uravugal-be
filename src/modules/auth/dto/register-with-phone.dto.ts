import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterWithPhoneDto {
  @ApiProperty({
    description: 'Firebase ID token from signInWithPhoneNumber + confirm()',
  })
  @IsString()
  @IsNotEmpty()
  firebaseIdToken: string;

  @ApiProperty({ example: 'password123', minLength: 6 })
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters' })
  @IsNotEmpty()
  password: string;
}
