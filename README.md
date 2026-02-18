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

### 2. Database (Docker — recommended)

Start PostgreSQL with fixed credentials (no manual user/database setup):

```bash
docker compose up -d postgres
```

Your `.env` already uses these credentials. If you copy from `.env.example`, it matches.

**Without Docker:** install PostgreSQL, create user/database, and set `DATABASE_URL` in `.env` to match.

### 3. Run migrations

```bash
npm run prisma:migrate
```

### 4. Seed (optional)

```bash
npm run prisma:seed
```

Creates users with **known passwords** (dev only):

| Email               | Password  | Role  |
|---------------------|-----------|--------|
| admin@example.com   | admin123  | ADMIN  |
| test@example.com    | test123   | USER   |

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
