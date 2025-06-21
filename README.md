# FastAPI Boilerplate Project

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-yellow)](https://github.com/)

A modular and extensible FastAPI project scaffold supporting PostgreSQL 17, Alembic migrations, JWT-based authentication with RBAC, versioned APIs (v1, v2), and automated testing using `pytest`. It includes Pydantic models and validation, async SQLAlchemy ORM, structured logging, and production-ready Docker support.

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
  - [Running Locally (without Docker)](#running-locally-without-docker)
- [🧬 API Versioning](#-api-versioning)
- [🔐 Authentication & RBAC](#-authentication--rbac)
- [📆 Models, Schemas, and Services](#-models-schemas-and-services)
- [🔍 Validators](#-validators)
- [🧰 Alembic Migrations](#-alembic-migrations)
- [🧪 Testing Strategy](#-testing-strategy)
- [📖 Adding Tests with Pytest](#-adding-tests-with-pytest)
- [📚 OpenAPI 3 Docs](#-openapi-3-docs)
- [📦 Dependency List](#-dependency-list)
- [📜 License](#-license)

---

## 🚀 Overview

This boilerplate includes:

- 🧱 **FastAPI** with async `SQLAlchemy` & `databases`
- 🐘 PostgreSQL 17
- 🔐 JWT authentication with Role-Based Access Control (RBAC)
- 🔁 API versioning support (v1, v2)
- 🧼 Alembic for migrations
- 🥪 `pytest`, `pytest-asyncio`, and `pytest-alembic` for tests
- 📆 Pydantic-based request validation
- 🔍 Interactive OpenAPI 3 documentation
- 🐳 Dockerized environment

---

## 📁 Project Structure

The core structure reflects versioned APIs and separation of concerns:

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

Edit `.env` file with:

```env
POSTGRES_DB=app
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_PORT=5432
JWT_SECRET_KEY=super-secret
```

### Using Docker & Docker Compose

```bash
docker-compose up --build
```

### Running Locally (without Docker)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## 🧬 API Versioning

API versions live in `app/api/v1/` and `app/api/v2/`. Each version:
- Defines independent routes
- Has its own services, schemas, and validators

Mounting happens in `api/routes/api.py` and registered in `main.py`.

---

## 🔐 Authentication & RBAC

Auth is handled via JWT tokens (see `security/jwt.py`). Role-based access control:
- Enforced in `dependencies/permissions.py`
- Uses role values defined in the database (via Alembic or SQL)

---

## 📆 Models, Schemas, and Services

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

Use `validators/*.py` to:
- Pre-validate complex business logic
- Separate validation logic from routes and schemas

Best practice: call validators from within services or route handlers.

---

## 🧰 Alembic Migrations

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

Test directory: `tests/`

Tests include:
- Unit tests for users, roles, login, registration
- Route tests
- Validation logic

Run tests:

```bash
pytest
```

---

## 📖 Adding Tests with Pytest

All test modules must be named `test_*.py`.
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

## 📚 OpenAPI 3 Docs

Visit interactive docs:

- Swagger UI: `http://localhost:8000/api/v1/docs`
- Redoc: `http://localhost:8000/api/v1/redoc`

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

---

## 📜 License

Licensed under the [MIT License](./LICENSE).

