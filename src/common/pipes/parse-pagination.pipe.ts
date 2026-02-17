import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';

export interface PaginationDto {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  search?: string;
  role?: string;
}

@Injectable()
export class ParsePaginationPipe implements PipeTransform {
  private readonly defaultLimit = 20;
  private readonly maxLimit = 100;
  private readonly allowedSortFields = [
    'createdAt',
    'updatedAt',
    'name',
    'email',
    'role',
  ];

  transform(value: Record<string, string>, _metadata: ArgumentMetadata): PaginationDto {
    const page = Math.max(1, parseInt(value?.page ?? '1', 10) || 1);
    const limit = Math.min(
      this.maxLimit,
      Math.max(1, parseInt(value?.limit ?? String(this.defaultLimit), 10) || this.defaultLimit),
    );
    const sortBy = value?.sortBy ?? 'createdAt';
    const sortOrder =
      (value?.sortOrder?.toLowerCase() === 'asc' ? 'asc' : 'desc') as 'asc' | 'desc';

    if (!this.allowedSortFields.includes(sortBy)) {
      throw new BadRequestException(
        `sortBy must be one of: ${this.allowedSortFields.join(', ')}`,
      );
    }

    return {
      page,
      limit,
      sortBy,
      sortOrder,
      search: value?.search?.trim() || undefined,
      role: value?.role?.trim() || undefined,
    };
  }
}
