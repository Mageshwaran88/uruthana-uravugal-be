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
}
