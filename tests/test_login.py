# tests/test_login.py

import pytest
from httpx import AsyncClient
from app.main import app
from app.core.db.session import async_session_maker
from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.security.passwords import get_password_hash
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
async def create_test_user() -> dict:
    async with async_session_maker() as session:
        # Create role
        role = Role(name="tester", permissions=["login"])
        session.add(role)
        await session.commit()
        await session.refresh(role)

        # Create user
        user = User(
            email="test_login@example.com",
            username="loginuser",
            password_hash=get_password_hash("securepassword123"),
            role_id=role.id,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        return {
            "email": user.email,
            "username": user.username,
            "password": "securepassword123"
        }


@pytest.mark.asyncio
async def test_login_success(create_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "username": create_test_user["username"],
            "password": create_test_user["password"]
        }
        response = await ac.post("/api/v1/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(create_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "username": create_test_user["username"],
            "password": "wrongpassword"
        }
        response = await ac.post("/api/v1/login", json=payload)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_nonexistent_user():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "username": "notrealuser",
            "password": "irrelevant"
        }
        response = await ac.post("/api/v1/login", json=payload)
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"

