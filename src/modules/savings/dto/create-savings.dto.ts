import { IsDateString, IsEnum, IsNotEmpty, IsNumber, IsOptional, IsString, IsUUID, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { TransactionType } from '@prisma/client';

export class CreateSavingsDto {
  @ApiProperty({ example: 100.5 })
  @IsNumber()
  @Min(0.01, { message: 'Amount must be positive' })
  @IsNotEmpty()
  amount: number;

  @ApiProperty({ enum: ['CREDIT', 'DEBIT'], default: 'CREDIT' })
  @IsOptional()
  @IsEnum(TransactionType)
  type?: TransactionType;

  @ApiProperty({ example: '2025-02-17' })
  @IsDateString()
  @IsNotEmpty()
  date: string;

  @ApiProperty({ example: 'Friend contribution', required: false })
  @IsOptional()
  @IsString()
  note?: string;

  @ApiProperty({ example: 'uuid-of-friend', required: false })
  @IsOptional()
  @IsUUID()
  contributorId?: string;

  @ApiProperty({ example: 'uuid-of-user', required: false, description: 'Admin only: target user' })
  @IsOptional()
  @IsUUID()
  userId?: string;
}
