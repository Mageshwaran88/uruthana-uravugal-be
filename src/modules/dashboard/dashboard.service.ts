import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export interface DashboardStats {
  totalUsers: number;
  totalAdmins: number;
  totalRegularUsers: number;
  usersThisWeek: number;
}

export interface DashboardChartData {
  label: string;
  value: number;
}

export interface AdminSavingsReport {
  totalSavings: number;
  userCount: number;
  byUser: Array<{ userId: string; userName: string; totalAmount: number }>;
  trend: DashboardChartData[];
}

@Injectable()
export class DashboardService {
  constructor(private prisma: PrismaService) {}

  async getStats(): Promise<DashboardStats> {
    const [totalUsers, totalAdmins, totalRegularUsers, usersThisWeek] =
      await Promise.all([
        this.prisma.user.count({ where: { deletedAt: null } }),
        this.prisma.user.count({
          where: { deletedAt: null, role: 'ADMIN' },
        }),
        this.prisma.user.count({
          where: { deletedAt: null, role: 'USER' },
        }),
        this.prisma.user.count({
          where: {
            deletedAt: null,
            createdAt: {
              gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
            },
          },
        }),
      ]);

    return {
      totalUsers,
      totalAdmins,
      totalRegularUsers,
      usersThisWeek,
    };
  }

  async getActivityChart(): Promise<DashboardChartData[]> {
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const result: DashboardChartData[] = [];
    const now = new Date();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const next = new Date(d);
      next.setDate(next.getDate() + 1);

      const count = await this.prisma.user.count({
        where: {
          deletedAt: null,
          createdAt: {
            gte: d,
            lt: next,
          },
        },
      });

      result.push({
        label: days[d.getDay()],
        value: count,
      });
    }

    return result;
  }

  async getWeeklyTrend(): Promise<DashboardChartData[]> {
    return this.getActivityChart();
  }

  async getAdminSavingsReport(): Promise<AdminSavingsReport> {
    const [creditAgg, debitAgg, byUserType, trendData] = await Promise.all([
      this.prisma.savingsRecord.aggregate({
        where: { type: 'CREDIT' },
        _sum: { amount: true },
      }),
      this.prisma.savingsRecord.aggregate({
        where: { type: 'DEBIT' },
        _sum: { amount: true },
      }),
      this.prisma.savingsRecord.groupBy({
        by: ['userId', 'type'],
        _sum: { amount: true },
      }),
      this.getSavingsTrend(7),
    ]);

    const totalSavings =
      Number(creditAgg._sum.amount ?? 0) - Number(debitAgg._sum.amount ?? 0);
    const userIds = [...new Set(byUserType.map((g) => g.userId))];
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, name: true },
    });
    const userMap = new Map(users.map((u) => [u.id, u.name]));
    const byUser = userIds.map((userId) => {
      const credit = byUserType.find((x) => x.userId === userId && x.type === 'CREDIT');
      const debit = byUserType.find((x) => x.userId === userId && x.type === 'DEBIT');
      const totalAmount =
        Number(credit?._sum.amount ?? 0) - Number(debit?._sum.amount ?? 0);
      return {
        userId,
        userName: userMap.get(userId) ?? 'Unknown',
        totalAmount,
      };
    });

    return {
      totalSavings,
      userCount: userIds.length,
      byUser,
      trend: trendData,
    };
  }

  private async getSavingsTrend(days: number): Promise<DashboardChartData[]> {
    const result: DashboardChartData[] = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const next = new Date(d);
      next.setDate(next.getDate() + 1);
      const [credit, debit] = await Promise.all([
        this.prisma.savingsRecord.aggregate({
          where: { date: { gte: d, lt: next }, type: 'CREDIT' },
          _sum: { amount: true },
        }),
        this.prisma.savingsRecord.aggregate({
          where: { date: { gte: d, lt: next }, type: 'DEBIT' },
          _sum: { amount: true },
        }),
      ]);
      const net =
        Number(credit._sum.amount ?? 0) - Number(debit._sum.amount ?? 0);
      result.push({
        label: d.toISOString().slice(0, 10),
        value: net,
      });
    }
    return result;
  }
}
