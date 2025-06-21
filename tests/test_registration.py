# tests/test_registration.py

import pytest
from httpx import AsyncClient
from app.main import app
from app.core.db.session import async_session_maker
from app.api.v1.models.role import Role
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
async def create_test_role():
    async with async_session_maker() as session:
        role = Role(name="member", permissions=["read"])
        session.add(role)
        await session.commit()
        await session.refresh(role)
        return role.id


@pytest.mark.asyncio
async def test_register_success(create_test_role):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "strongpass123",
            "role_id": create_test_role
        }
        response = await ac.post("/api/v1/register", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert "id" in data
        assert "password" not in data  # Ensure password is excluded


@pytest.mark.asyncio
async def test_register_existing_email(create_test_role):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {
            "email": "dupe@example.com",
            "username": "dupeuser1",
            "password": "pass123",
            "role_id": create_test_role
        }
        await ac.post("/api/v1/register", json=payload)

        payload["username"] = "dupeuser2"
        response = await ac.post("/api/v1/register", json=payload)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_register_existing_username(create_test_role):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload1 = {
            "email": "unique1@example.com",
            "username": "repeatuser",
            "password": "pass123",
            "role_id": create_test_role
        }
        await ac.post("/api/v1/register", json=payload1)

        payload2 = {
            "email": "unique2@example.com",
            "username": "repeatuser",
            "password": "pass456",
            "role_id": create_test_role
        }
        response = await ac.post("/api/v1/register", json=payload2)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

