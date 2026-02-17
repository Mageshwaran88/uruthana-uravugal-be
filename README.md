# Uruthana Uravugal Backend

NestJS backend with PostgreSQL, Prisma, JWT auth, RBAC, and CRUD.

## Features

- **Auth**: JWT access + refresh tokens, Argon2 password hashing
- **Users**: CRUD, pagination, soft delete, avatar upload
- **RBAC**: Role-based access (USER, ADMIN)
- **API**: Swagger docs, validation, rate limiting, Helmet

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Database

Ensure PostgreSQL is running. Create a database:

```sql
CREATE DATABASE uruthana_uravugal;
```

Copy `.env.example` to `.env` and set `DATABASE_URL`:

```
DATABASE_URL="postgresql://user:password@localhost:5432/uruthana_uravugal?schema=public"
```

### 3. Run migrations

```bash
npm run prisma:migrate
```

### 4. Seed (optional)

```bash
npm run prisma:seed
```

Creates admin user: `admin@example.com` / `admin123`

### 5. Start

```bash
npm run start:dev
```

- API: http://localhost:3001/api
- Swagger: http://localhost:3001/api/docs

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/auth/login | - | Login |
| POST | /api/auth/register | - | Register |
| POST | /api/auth/refresh | Cookie | Refresh token |
| POST | /api/auth/logout | JWT | Logout |
| GET | /api/auth/me | JWT | Current user |
| POST | /api/auth/change-password | JWT | Change password |
| POST | /api/auth/forgot-password | - | Forgot password |
| POST | /api/auth/reset-password | - | Reset with token |
| GET | /api/users | Admin | List users (paginated) |
| GET | /api/users/me | JWT | Current user profile |
| POST | /api/users/me/avatar | JWT | Upload avatar |
| GET | /api/users/:id | JWT | Get user by ID |
