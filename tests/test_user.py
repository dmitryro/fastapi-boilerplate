import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.api.v1.models.user import User
from app.core.db.session import get_db
from app.api.v1.schemas.user import UserCreate
from app.api.v1.security.passwords import get_password_hash
from fastapi import status


@pytest.fixture
async def create_test_user(async_session: AsyncSession) -> User:
    user = User(
        email="testuser@example.com",
        username="testuser",
        password_hash=get_password_hash("testpassword"),
        role_id=2  # assume 2 is a basic user
    )
    async_session.add(user)
    await async_session.commit()
    await async_session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_create_user(async_session: AsyncSession):
    async with AsyncClient(app=app, base_url="http://test") as client:
        payload = {
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "securepass",
            "role_id": 2
        }
        response = await client.post("/api/v1/users", json=payload)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert "id" in data


@pytest.mark.asyncio
async def test_get_user(create_test_user: User):
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(f"/api/v1/users/{create_test_user.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == create_test_user.email
        assert data["username"] == create_test_user.username


@pytest.mark.asyncio
async def test_get_user_not_found():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/v1/users/9999")
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_list_users(create_test_user: User):
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/v1/users")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert any(user["email"] == create_test_user.email for user in data)

