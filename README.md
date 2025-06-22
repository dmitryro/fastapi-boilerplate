
# FastAPI Boilerplate Project

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-yellow)](https://github.com/)

A modular and extensible FastAPI project scaffold supporting PostgreSQL 17, Alembic migrations, JWT-based authentication with RBAC, versioned APIs (v1, v2), Redis cache layer, and automated testing using `pytest`. It includes Pydantic models and validation, async SQLAlchemy ORM, structured logging, and production-ready Docker support.

**Version**: 1.0.0  
**License**: [MIT License](./LICENSE)

---

## 📁 Contents

- [🚀 Overview](#-overview)
- [📁 Project Structure](#-project-structure)
- [🛠 Setup Instructions](#-setup-instructions)
  - [Clone & Configure](#clone--configure)
  - [Environment Variables](#environment-variables)
  - [Using Docker & Docker Compose](#using-docker--docker-compose)
  - [Using Redis Cache Layer](#using-redis-cache-layer)
  - [Running Locally (without Docker)](#running-locally-without-docker)
- [🧬 API Versioning](#-api-versioning)
- [🔐 Authentication & RBAC](#-authentication--rbac)
  - [Initial Roles Setup](#initial-roles-setup)
  - [Adding New Roles and Permissions](#adding-new-roles-and-permissions)
  - [Permission Enforcement](#permission-enforcement)
- [🔐 Auth Dependencies](#-auth-dependencies)
- [🔐 Password Hashing and Verification](#-password-hashing-and-verification)
- [🔐 JWT Token Utilities](#-jwt-token-utilities)
- [📆 Models, Schemas, and Services](#-models-schemas-and-services)
- [🔍 Validators](#-validators)
- [🧰 Alembic Migrations](#-alembic-migrations)
- [🧪 Testing Strategy](#-testing-strategy)
- [📖 Adding Tests with Pytest](#-adding-tests-with-pytest)
- [📚 OpenAPI 3 Docs](#-openapi-3-docs)
- [📦 Dependency List](#-dependency-list)
- [⚙️ Database Access and Async Setup](#-database-access-and-async-setup)
- [📜 License](#-license)

---

## 🚀 Overview

This boilerplate includes:

- 🧱 **FastAPI** with async `SQLAlchemy` & `databases[asyncpg]`
- 🐘 PostgreSQL 17 with psycopg2 & asyncpg support
- 🔐 JWT authentication with Role-Based Access Control (RBAC)
- 🔁 API versioning support (v1, v2)
- 🧼 Alembic for migrations
- 🧠 Redis cache layer (optional)
- 🥪 `pytest`, `pytest-asyncio`, and `pytest-alembic` for tests
- 📆 Pydantic-based request validation
- 🔍 Interactive OpenAPI 3 documentation
- 🐳 Dockerized environment with PostgreSQL and Redis support

---

## 📁 Project Structure

```
app/
├── api/
│   ├── routes/
│   ├── v1/
│   │   ├── dependencies/
│   │   ├── models/
│   │   ├── routes/
│   │   ├── schemas/
│   │   ├── security/
│   │   ├── services/
│   │   └── validators/
│   └── v2/
├── core/ (settings, events, db, logging)
├── main.py
└── models/
```

---

## 🛠 Setup Instructions

### Clone & Configure

```bash
git clone https://github.com/your-username/fastapi-boilerplate.git
cd fastapi-boilerplate
cp .env_template .env
```

### Environment Variables

```env
POSTGRES_DB=appdb
POSTGRES_USER=admin
POSTGRES_PASSWORD=secret
POSTGRES_PORT=5432

REDIS_HOST=redis
REDIS_PORT=6379

JWT_SECRET_KEY=super-secret
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=postgresql+asyncpg://admin:secret@db:5432/appdb
```

### Using Docker & Docker Compose

```bash
docker-compose up --build
```

**docker-compose.yaml:**

```
version: '3.9'
services:
  db:
    image: postgres:17
    container_name: postgres17
    restart: always
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: secret
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7
    container_name: redis
    restart: always
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data

  api:
    build: .
    command: ["python", "run_app.py"]
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      - db
      - redis

volumes:
  pgdata:
  redisdata:
```

### Using Redis Cache Layer

Use `redis.asyncio` in your services or dependencies.

- Cache user sessions, tokens, or heavy queries
- Invalidate on updates where needed

---

### Running Locally (without Docker)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## 🧬 API Versioning

Versions are mounted in `api/routes/api.py`.
API versions live in `app/api/v1/` and `app/api/v2/`. Each version:
- Defines independent routes
- Has its own services, schemas, and validators

Mounting happens in `api/routes/api.py` and registered in `main.py`.

---

## 🔐 Authentication & RBAC

RBAC is based on a `roles` table with an array of permissions.

Auth is handled via JWT tokens (see `security/jwt.py`). Role-based access control:
- Enforced in `dependencies/permissions.py`
- Uses role values defined in the database (via Alembic or SQL)

---

### Initial Roles Setup

```sql
INSERT INTO roles (id, name, permissions)
VALUES
  (1, 'admin', ARRAY['create','read','update','delete','superuser']),
  (2, 'guest', ARRAY['read'])
ON CONFLICT DO NOTHING;
```

### Adding New Roles and Permissions

```sql
INSERT INTO roles (name, permissions) VALUES ('editor', ARRAY['read', 'update']);
```

### Permission Enforcement

Use `require_permission` from `dependencies/permissions.py`:

```python
@router.get("/users", dependencies=[Depends(require_permission("read"))])
async def get_users():
    ...
```

---

## 🔐 Auth Dependencies

File: `app/api/v1/dependencies/auth.py`

- Extracts token
- Decodes JWT
- Retrieves user from DB

---

## 🔐 Password Hashing and Verification

File: `app/api/v1/security/passwords.py`

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hashed_password: str, plain_password: str) -> bool:
    return ph.verify(hashed_password, plain_password)
```

---

## 🔐 JWT Token Utilities

File: `app/api/v1/security/jwt.py`

- Generates token via `create_access_token(data)`
- Decodes token using `decode_jwt(token)`
- Supports fallback auth via Bearer or Basic
- Uses FastAPI security schemes

---

## 📆 Models, Schemas, and Services

- Models: SQLAlchemy, async
- Schemas: Pydantic
- Services: Business logic layer

### Models
Defined in `v1/models` using SQLAlchemy.

### Schemas (Pydantic)
Defined in `v1/schemas`. Use `BaseModel` to:
- Control validation
- Shape response and request bodies
- Avoid leaking sensitive fields

### Services
Business logic lives in `v1/services`. 
Usage:
```python
from app.api.v1.services.user import get_user_by_id
user = await get_user_by_id(user_id)
```
Use services inside route handlers to keep them thin.

---


## 🔍 Validators

Use validators to separate validation from routing. Useful for complex pre-checks.

Use `validators/*.py` to:
- Pre-validate complex business logic
- Separate validation logic from routes and schemas

Best practice: call validators from within services or route handlers.

---

## 🧰 Alembic Migrations

```bash
alembic revision --autogenerate -m "message"
alembic upgrade head
```

### Creating a Migration

```bash
alembic revision --autogenerate -m "create user and role tables"
```

### Applying Migrations

```bash
alembic upgrade head
```

Alembic config is in `alembic.ini`. Migrations use the `app.core.db.session.Base` metadata.

---


## 🧪 Testing Strategy

Async tests under `tests/`:

```bash
pytest --cov=app --cov-report=term-missing -v --log-cli-level=DEBUG
```

To test, for example, users route, run:

```bash
pytest tests/test_user.py
```

Tests include:
- Unit tests for users, roles, login, registration
- Route tests
- Validation logic

---

## 📖 Adding Tests with Pytest

All test modules must be named `test_*.py`.
Use `pytest-asyncio`. Shared fixtures for DB overrides.
Fixtures, mocks, and DB overrides should be reused across test cases.

Test file layout:
```
tests/
├── test_user.py
├── test_role.py
├── test_login.py
├── test_registration.py
├── test_routes.py
├── test_validation.py
```

To write a new test:
```python
def test_example():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
```

Use `pytest-asyncio` for async test functions.

---
---

## 📚 OpenAPI 3 Docs

- Swagger: http://localhost:8000/api/v1/docs
- Redoc: http://localhost:8000/api/v1/redoc

---

## 📦 Dependency List

Key packages:
- `fastapi`, `uvicorn` - web framework
- `sqlalchemy`, `databases` - async DB access
- `alembic` - migrations
- `pydantic` - validation
- `pytest`, `pytest-asyncio` - testing
- `python-jose` - JWT
- `argon2-cffi`, `passlib[bcrypt]` - password hashing
- `psycopg2` - optional sync access

---

## ⚙️ Database Access and Async Setup

Uses `databases` with `asyncpg`. DB URL: `postgresql+asyncpg://...`.

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
```

---

## 📜 License

MIT License
