import { IsDateString, IsEnum, IsIn, IsOptional, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { TransactionType } from '@prisma/client';

export enum SavingsPeriod {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
}

export class SavingsQueryDto {
  @ApiProperty({ enum: SavingsPeriod, required: false })
  @IsOptional()
  @IsEnum(SavingsPeriod)
  period?: SavingsPeriod;

  @ApiProperty({ example: '2025-02-01', required: false })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiProperty({ example: '2025-02-28', required: false })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiProperty({ enum: ['CREDIT', 'DEBIT'], required: false })
  @IsOptional()
  @IsEnum(TransactionType)
  type?: TransactionType;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsUUID()
  userId?: string;

  @ApiProperty({ example: 1, required: false })
  @IsOptional()
  page?: number;

  @ApiProperty({ example: 20, required: false })
  @IsOptional()
  limit?: number;

  @ApiProperty({ example: 'date', description: 'date | amount | createdAt', required: false })
  @IsOptional()
  @IsIn(['date', 'amount', 'createdAt'])
  sortBy?: string;

  @ApiProperty({ example: 'desc', required: false })
  @IsOptional()
  @IsIn(['asc', 'desc'])
  sortOrder?: 'asc' | 'desc';
}
