import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { join } from 'path';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const config = app.get(ConfigService);

  const prefix = config.get<string>('apiPrefix', 'api');
  app.setGlobalPrefix(prefix);

  app.use(cookieParser());
  app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

  app.useStaticAssets(join(process.cwd(), 'uploads'), {
    prefix: '/uploads/',
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  const corsOrigin = config.get<string>('cors.origin', 'http://localhost:3000');
  app.enableCors({
    origin: corsOrigin.split(',').map((o) => o.trim()),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  if (config.get('env') !== 'production') {
    const docConfig = new DocumentBuilder()
      .setTitle('Uruthana Uravugal API')
      .setDescription('Backend API documentation')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, docConfig);
    SwaggerModule.setup(`${prefix}/docs`, app, document);
  }

  const port = config.get<number>('port', 8000);
  await app.listen(port);
  console.log(`🚀 API running at http://localhost:${port}/${prefix}`);
  if (config.get('env') !== 'production') {
    console.log(`📚 Swagger at http://localhost:${port}/${prefix}/docs`);
  }
}
bootstrap();
