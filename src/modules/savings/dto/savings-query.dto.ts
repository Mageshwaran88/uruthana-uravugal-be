import { IsDateString, IsEnum, IsOptional, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

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
}
