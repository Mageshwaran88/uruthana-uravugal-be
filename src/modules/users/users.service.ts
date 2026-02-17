import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { Role } from '@prisma/client';
import { hashPassword } from '../../common/utils/hash.util';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PaginationDto } from '../../common/pipes/parse-pagination.pipe';
import { PaginatedResponse } from '../../common/dto/pagination.dto';

const userSelect = {
  id: true,
  name: true,
  email: true,
  mobile: true,
  avatarUrl: true,
  role: true,
  emailVerifiedAt: true,
  mobileVerifiedAt: true,
  createdAt: true,
  updatedAt: true,
};

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findAll(
    pagination: PaginationDto,
  ): Promise<PaginatedResponse<typeof userSelect extends object ? object : never>> {
    const { page, limit, sortBy, sortOrder, search, role } = pagination;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {
      deletedAt: null,
    };

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' as const } },
        { email: { contains: search, mode: 'insensitive' as const } },
        ...(search.includes('@')
          ? []
          : [{ mobile: { contains: search, mode: 'insensitive' as const } }]),
      ];
    }

    if (role) {
      where.role = role as Role;
    }

    const orderBy = { [sortBy as string]: sortOrder } as { createdAt?: 'asc' | 'desc'; updatedAt?: 'asc' | 'desc'; name?: 'asc' | 'desc'; email?: 'asc' | 'desc'; role?: 'asc' | 'desc' };
    const [data, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        select: userSelect,
        orderBy,
        skip,
        take: limit,
      }),
      this.prisma.user.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit);
    return {
      data: data as object[],
      meta: {
        total,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1,
      },
    };
  }

  async findById(id: string) {
    const user = await this.prisma.user.findFirst({
      where: { id, deletedAt: null },
      select: userSelect,
    });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async create(dto: CreateUserDto) {
    const email = dto.email.toLowerCase().trim();
    const existing = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, ...(dto.mobile ? [{ mobile: dto.mobile }] : [])],
        deletedAt: null,
      },
    });
    if (existing) {
      throw new ConflictException(
        existing.email === email ? 'Email already in use' : 'Mobile already in use',
      );
    }
    const passwordHash = await hashPassword(dto.password);
    const user = await this.prisma.user.create({
      data: {
        name: dto.name.trim(),
        email,
        mobile: dto.mobile?.trim() || null,
        passwordHash,
        role: dto.role ?? Role.USER,
      },
      select: userSelect,
    });
    return user;
  }

  async update(id: string, dto: UpdateUserDto) {
    await this.findById(id);
    const email = dto.email?.toLowerCase().trim();
    if (email) {
      const existing = await this.prisma.user.findFirst({
        where: {
          email,
          deletedAt: null,
          NOT: { id },
        },
      });
      if (existing) throw new ConflictException('Email already in use');
    }
    const user = await this.prisma.user.update({
      where: { id },
      data: {
        ...(dto.name && { name: dto.name.trim() }),
        ...(email && { email }),
        ...(dto.role && { role: dto.role }),
        ...(dto.mobile !== undefined && {
          mobile: dto.mobile?.trim() || null,
        }),
      },
      select: userSelect,
    });
    return user;
  }

  async softDelete(id: string) {
    await this.findById(id);
    await this.prisma.user.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
    return { message: 'User deleted successfully' };
  }

  async updateAvatar(userId: string, avatarUrl: string) {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { avatarUrl },
      select: userSelect,
    });
    return user;
  }
}
