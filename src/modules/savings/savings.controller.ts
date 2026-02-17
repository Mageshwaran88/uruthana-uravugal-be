import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Query,
  UseGuards,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser, CurrentUserPayload } from '../../common/decorators/current-user.decorator';
import { Role } from '@prisma/client';
import { SavingsService } from './savings.service';
import { CreateSavingsDto } from './dto/create-savings.dto';
import { CreditDebitDto } from './dto/credit-debit.dto';
import { UpdateSavingsDto } from './dto/update-savings.dto';
import { SavingsQueryDto } from './dto/savings-query.dto';
import * as ExcelJS from 'exceljs';

@ApiTags('savings')
@Controller('savings')
@UseGuards(JwtAuthGuard)
export class SavingsController {
  constructor(private savings: SavingsService) {}

  @Post('credit-debit')
  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: Credit or Debit user amount' })
  creditDebit(
    @CurrentUser() user: CurrentUserPayload,
    @Body() dto: CreditDebitDto,
  ) {
    return this.savings.creditDebit(user.id, dto);
  }

  @Post()
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Add savings record (credit)' })
  create(
    @CurrentUser() user: CurrentUserPayload,
    @Body() dto: CreateSavingsDto,
  ) {
    const isAdmin = user.role === Role.ADMIN;
    return this.savings.create(user.id, dto, isAdmin);
  }

  @Get()
  @ApiBearerAuth()
  @ApiOperation({ summary: 'List savings with filters' })
  @ApiQuery({ name: 'period', required: false })
  @ApiQuery({ name: 'fromDate', required: false })
  @ApiQuery({ name: 'toDate', required: false })
  @ApiQuery({ name: 'userId', required: false })
  @ApiQuery({ name: 'page', required: false })
  @ApiQuery({ name: 'limit', required: false })
  findAll(
    @CurrentUser() user: CurrentUserPayload,
    @Query() query: SavingsQueryDto,
  ) {
    return this.savings.findAll(
      user.id,
      user.role as Role,
      query,
    );
  }

  @Get('summary')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get total, daily, weekly, monthly summary' })
  @ApiQuery({ name: 'userId', required: false })
  getSummary(
    @CurrentUser() user: CurrentUserPayload,
    @Query('userId') userId?: string,
  ) {
    return this.savings.getSummary(
      user.id,
      user.role as Role,
      userId,
    );
  }

  @Get('admin/overall')
  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: overall total saved' })
  getAdminOverall() {
    return this.savings.getAdminOverallTotal();
  }

  @Get('admin/by-user')
  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Admin: per-user savings' })
  getAdminByUser() {
    return this.savings.getAdminUserSavings();
  }

  @Get('report')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Download report (Excel)' })
  @ApiQuery({ name: 'format', required: false })
  @ApiQuery({ name: 'fromDate', required: false })
  @ApiQuery({ name: 'toDate', required: false })
  @ApiQuery({ name: 'userId', required: false })
  async downloadReport(
    @CurrentUser() user: CurrentUserPayload,
    @Res({ passthrough: false }) res: Response,
    @Query('fromDate') fromDate?: string,
    @Query('toDate') toDate?: string,
    @Query('userId') userId?: string,
  ) {
    const isAdmin = user.role === Role.ADMIN;
    const targetUserId = isAdmin && userId ? userId : user.id;
    const { data } = await this.savings.findAll(
      user.id,
      user.role as Role,
      { fromDate, toDate, userId: targetUserId, limit: 10000 },
    );

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Savings Report');
    sheet.columns = [
      { header: 'Date', key: 'date', width: 12 },
      { header: 'Type', key: 'type', width: 10 },
      { header: 'Amount', key: 'amount', width: 14 },
      { header: 'Note', key: 'note', width: 30 },
      { header: 'Created By', key: 'createdByName', width: 20 },
      { header: 'User', key: 'userName', width: 20 },
    ];
    sheet.addRows(data);

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    );
    res.setHeader(
      'Content-Disposition',
      `attachment; filename=savings-report-${new Date().toISOString().slice(0, 10)}.xlsx`,
    );
    await workbook.xlsx.write(res);
  }

  @Get(':id')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get record by ID' })
  @ApiParam({ name: 'id' })
  findOne(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: CurrentUserPayload,
  ) {
    return this.savings.findOne(id, user.id, user.role as Role);
  }

  @Put(':id')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update record' })
  @ApiParam({ name: 'id' })
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateSavingsDto,
    @CurrentUser() user: CurrentUserPayload,
  ) {
    return this.savings.update(id, dto, user.id, user.role as Role);
  }

  @Delete(':id')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete record' })
  @ApiParam({ name: 'id' })
  remove(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: CurrentUserPayload,
  ) {
    return this.savings.remove(id, user.id, user.role as Role);
  }
}
