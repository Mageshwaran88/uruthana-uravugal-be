import {
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { Role } from '@prisma/client';
import { Decimal } from '@prisma/client/runtime/library';
import { CreateSavingsDto } from './dto/create-savings.dto';
import { UpdateSavingsDto } from './dto/update-savings.dto';
import { SavingsQueryDto } from './dto/savings-query.dto';
import { encryptAmount } from '../../common/utils/crypto.util';

export interface SavingsRecordResponse {
  id: string;
  amount: string;
  type: 'CREDIT' | 'DEBIT';
  amountEncrypted: string;
  date: string;
  note: string | null;
  contributorName?: string | null;
  userName?: string;
  createdByName: string;
  createdById: string;
  createdAt: string;
}

export interface SavingsSummary {
  total: number;
  daily: number;
  weekly: number;
  monthly: number;
}

@Injectable()
export class SavingsService {
  constructor(private prisma: PrismaService) {}

  private encryptValue(val: Decimal | number): string {
    const num = typeof val === 'object' ? Number(val) : val;
    return encryptAmount(num.toFixed(2));
  }

  async create(userId: string, dto: CreateSavingsDto, isAdmin: boolean) {
    const targetUserId = isAdmin && dto.userId ? dto.userId : userId;
    const type = dto.type ?? 'CREDIT';
    if (!isAdmin && targetUserId !== userId) {
      throw new ForbiddenException('Cannot add savings for another user');
    }
    if (!isAdmin && type === 'DEBIT') {
      throw new ForbiddenException('Only admin can debit');
    }
    const record = await this.prisma.savingsRecord.create({
      data: {
        userId: targetUserId,
        amount: new Decimal(dto.amount),
        type: type ?? 'CREDIT',
        date: new Date(dto.date),
        note: dto.note,
        contributorId: dto.contributorId || null,
        createdById: userId,
      },
      include: {
        contributor: { select: { name: true } },
        user: { select: { name: true } },
        createdBy: { select: { name: true, id: true } },
      },
    });
    return this.toResponse(record);
  }

  async creditDebit(adminId: string, dto: { userId: string; amount: number; type: 'CREDIT' | 'DEBIT'; date: string; note?: string }) {
    const record = await this.prisma.savingsRecord.create({
      data: {
        userId: dto.userId,
        amount: new Decimal(dto.amount),
        type: dto.type,
        date: new Date(dto.date),
        note: dto.note || null,
        createdById: adminId,
      },
      include: {
        user: { select: { name: true } },
        createdBy: { select: { name: true, id: true } },
      },
    });
    return this.toResponse(record);
  }

  async findAll(
    currentUserId: string,
    currentRole: Role,
    query: SavingsQueryDto,
  ) {
    const userId = query.userId && currentRole === Role.ADMIN ? query.userId : currentUserId;
    const page = Math.max(1, query.page ?? 1);
    const limit = Math.min(100, Math.max(1, query.limit ?? 20));
    const skip = (page - 1) * limit;

    const fromDate = query.fromDate ? new Date(query.fromDate) : null;
    const toDate = query.toDate ? new Date(query.toDate) : null;

    const where: Record<string, unknown> = { userId };
    if (fromDate || toDate) {
      where.date = {};
      if (fromDate) (where.date as Record<string, Date>).gte = fromDate;
      if (toDate) (where.date as Record<string, Date>).lte = toDate;
    }
    if (query.type) {
      where.type = query.type;
    }

    const sortBy = query.sortBy ?? 'date';
    const sortOrder = query.sortOrder ?? 'desc';
    const orderBy = { [sortBy]: sortOrder } as { date?: 'asc' | 'desc'; amount?: 'asc' | 'desc'; createdAt?: 'asc' | 'desc' };

    const [records, total] = await Promise.all([
      this.prisma.savingsRecord.findMany({
        where,
        include: {
          contributor: { select: { id: true, name: true } },
          user: { select: { id: true, name: true } },
          createdBy: { select: { id: true, name: true } },
        },
        orderBy,
        skip,
        take: limit,
      }),
      this.prisma.savingsRecord.count({ where }),
    ]);

    const data = records.map((r) => this.toResponse(r));
    return {
      data,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(id: string, currentUserId: string, currentRole: Role) {
    const record = await this.prisma.savingsRecord.findUnique({
      where: { id },
      include: {
        contributor: { select: { name: true } },
        user: { select: { name: true } },
        createdBy: { select: { name: true, id: true } },
      },
    });
    if (!record) throw new NotFoundException('Record not found');
    if (currentRole !== Role.ADMIN && record.userId !== currentUserId) {
      throw new ForbiddenException('Access denied');
    }
    return this.toResponse(record);
  }

  async update(
    id: string,
    dto: UpdateSavingsDto,
    currentUserId: string,
    currentRole: Role,
  ) {
    const record = await this.prisma.savingsRecord.findUnique({
      where: { id },
    });
    if (!record) throw new NotFoundException('Record not found');
    if (currentRole !== Role.ADMIN && record.userId !== currentUserId) {
      throw new ForbiddenException('Access denied');
    }
    const updated = await this.prisma.savingsRecord.update({
      where: { id },
      data: {
        ...(dto.amount != null && { amount: new Decimal(dto.amount) }),
        ...(dto.date && { date: new Date(dto.date) }),
        ...(dto.note !== undefined && { note: dto.note }),
      },
      include: {
        contributor: { select: { name: true } },
        user: { select: { name: true } },
        createdBy: { select: { name: true, id: true } },
      },
    });
    return this.toResponse(updated);
  }

  async remove(id: string, currentUserId: string, currentRole: Role) {
    const record = await this.prisma.savingsRecord.findUnique({
      where: { id },
    });
    if (!record) throw new NotFoundException('Record not found');
    if (currentRole !== Role.ADMIN && record.userId !== currentUserId) {
      throw new ForbiddenException('Access denied');
    }
    await this.prisma.savingsRecord.delete({ where: { id } });
    return { message: 'Deleted successfully' };
  }

  async getSummary(
    currentUserId: string,
    currentRole: Role,
    userId?: string,
  ): Promise<SavingsSummary> {
    const targetUserId =
      currentRole === Role.ADMIN && userId ? userId : currentUserId;
    if (currentRole !== Role.ADMIN && targetUserId !== currentUserId) {
      throw new ForbiddenException('Access denied');
    }

    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(today);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const where = { userId: targetUserId };
    const calc = async (w: Record<string, unknown>) => {
      const [credit, debit] = await Promise.all([
        this.prisma.savingsRecord.aggregate({
          where: { ...w, type: 'CREDIT' },
          _sum: { amount: true },
        }),
        this.prisma.savingsRecord.aggregate({
          where: { ...w, type: 'DEBIT' },
          _sum: { amount: true },
        }),
      ]);
      return Number(credit._sum.amount ?? 0) - Number(debit._sum.amount ?? 0);
    };
    const [total, daily, weekly, monthly] = await Promise.all([
      calc(where),
      calc({ ...where, date: { gte: today } }),
      calc({ ...where, date: { gte: weekStart } }),
      calc({ ...where, date: { gte: monthStart } }),
    ]);

    return { total, daily, weekly, monthly };
  }

  async getAdminOverallTotal(): Promise<{ total: number; userCount: number }> {
    const [credit, debit, userCount] = await Promise.all([
      this.prisma.savingsRecord.aggregate({
        where: { type: 'CREDIT' },
        _sum: { amount: true },
      }),
      this.prisma.savingsRecord.aggregate({
        where: { type: 'DEBIT' },
        _sum: { amount: true },
      }),
      this.prisma.savingsRecord.groupBy({ by: ['userId'] }),
    ]);
    const total = Number(credit._sum.amount ?? 0) - Number(debit._sum.amount ?? 0);
    return { total, userCount: userCount.length };
  }

  async getAdminUserSavings() {
    const userIds = await this.prisma.savingsRecord.findMany({
      distinct: ['userId'],
      select: { userId: true },
    });
    const ids = userIds.map((u) => u.userId);
    const users = await this.prisma.user.findMany({
      where: { id: { in: ids } },
      select: { id: true, name: true, email: true },
    });
    const userMap = new Map(users.map((u) => [u.id, u]));
    const result = await Promise.all(
      ids.map(async (uid) => {
        const [credit, debit, count] = await Promise.all([
          this.prisma.savingsRecord.aggregate({
            where: { userId: uid, type: 'CREDIT' },
            _sum: { amount: true },
          }),
          this.prisma.savingsRecord.aggregate({
            where: { userId: uid, type: 'DEBIT' },
            _sum: { amount: true },
          }),
          this.prisma.savingsRecord.count({ where: { userId: uid } }),
        ]);
        const total = Number(credit._sum.amount ?? 0) - Number(debit._sum.amount ?? 0);
        return {
          userId: uid,
          userName: userMap.get(uid)?.name ?? 'Unknown',
          userEmail: userMap.get(uid)?.email ?? null,
          totalAmount: total.toFixed(2),
          totalAmountEncrypted: this.encryptValue(total),
          recordCount: count,
        };
      })
    );
    return result;
  }

  private toResponse(record: {
    id: string;
    amount: Decimal;
    type: 'CREDIT' | 'DEBIT';
    date: Date;
    note: string | null;
    createdAt: Date;
    contributor?: { name: string } | null;
    user?: { name: string } | null;
    createdBy?: { name: string; id: string } | null;
  }): SavingsRecordResponse {
    const amountNum = Number(record.amount);
    return {
      id: record.id,
      amount: amountNum.toFixed(2),
      type: record.type,
      amountEncrypted: this.encryptValue(record.amount),
      date: record.date.toISOString().slice(0, 10),
      note: record.note,
      contributorName: record.contributor?.name ?? null,
      userName: record.user?.name ?? undefined,
      createdByName: record.createdBy?.name ?? 'System',
      createdById: record.createdBy?.id ?? '',
      createdAt: record.createdAt.toISOString(),
    };
  }
}
