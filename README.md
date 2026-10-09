# LangGraph API

## Local startup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload
```

The default database is MySQL. Before starting the application, update `DATABASE_URL` in `.env` with your MySQL credentials and database name, for example:

```dotenv
DATABASE_URL=mysql+pymysql://root:your-password@localhost:3306/langgraph?charset=utf8mb4
```

Create the database once if it does not exist:

```sql
CREATE DATABASE langgraph CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Development runs Alembic migrations at startup. In production, run migrations during deployment:

```bash
alembic upgrade head
```

Production must set:

- `ENVIRONMENT=production`
- a random `JWT_SECRET_KEY` with at least 32 characters
- explicit `CORS_ORIGINS` and `ALLOWED_HOSTS`
- `RATE_LIMIT_STORAGE_URI` using shared storage such as Redis
- a production database URL such as PostgreSQL or MySQL

Production disables Swagger and does not run migrations automatically. Login, registration, and token refresh endpoints are rate-limited.

## Authentication flow

1. `POST /api/v1/auth/register` creates a normal user. Passwords require at least 12 characters.
2. `POST /api/v1/auth/login` accepts form fields `username=<email>&password=<password>`.
3. Send `Authorization: Bearer <access_token>` to protected endpoints.
4. Use `POST /api/v1/auth/refresh` to rotate an expired access token.
5. Refresh tokens are stored only as hashes. Reuse of a revoked token revokes its entire session family.
6. `POST /api/v1/auth/logout` revokes the current refresh token.
7. `POST /api/v1/auth/password` changes the password and revokes all refresh sessions.

## Authorization endpoints

- Authenticated users: `GET /api/v1/profile`, `GET /api/v1/auth/me`
- Administrators: `GET /api/v1/admin/users`
- Administrators: `PATCH /api/v1/admin/users/{user_id}/role`
- Administrators: `PATCH /api/v1/admin/users/{user_id}/status`

Set `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD` together to provision the first administrator. Existing accounts are never overwritten.

Health checks:

- `/health/live`: process liveness
- `/health/ready`: process and database readiness
