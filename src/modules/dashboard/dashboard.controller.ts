import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { DashboardService } from './dashboard.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';

@ApiTags('dashboard')
@Controller('dashboard')
@UseGuards(JwtAuthGuard)
export class DashboardController {
  constructor(private dashboard: DashboardService) {}

  @Get('stats')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get dashboard statistics' })
  getStats() {
    return this.dashboard.getStats();
  }

  @Get('activity')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get activity chart data' })
  getActivityChart() {
    return this.dashboard.getActivityChart();
  }

  @Get('report')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get full dashboard report' })
  async getReport() {
    const [stats, activityChart, weeklyTrend] = await Promise.all([
      this.dashboard.getStats(),
      this.dashboard.getActivityChart(),
      this.dashboard.getWeeklyTrend(),
    ]);
    return {
      stats,
      barChart: {
        title: 'Activity Summary',
        dataKey: 'value',
        nameKey: 'label',
        data: activityChart,
      },
      lineChart: {
        title: 'Weekly Trend',
        dataKey: 'value',
        nameKey: 'label',
        data: weeklyTrend,
      },
    };
  }
}
