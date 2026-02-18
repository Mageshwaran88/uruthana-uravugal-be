import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  async cleanDb() {
    const prisma = this as unknown as {
      refreshToken: { deleteMany: () => Promise<unknown> };
      passwordResetToken: { deleteMany: () => Promise<unknown> };
      otpVerification: { deleteMany: () => Promise<unknown> };
      savingsRecord: { deleteMany: () => Promise<unknown> };
      user: { deleteMany: () => Promise<unknown> };
    };
    await prisma.refreshToken.deleteMany();
    await prisma.passwordResetToken.deleteMany();
    await prisma.otpVerification.deleteMany();
    await prisma.savingsRecord.deleteMany();
    await prisma.user.deleteMany();
  }
}
