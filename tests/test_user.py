import pytest
from unittest.mock import AsyncMock, patch, ANY
from datetime import datetime
from fastapi import status
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from app.main import app
from app.core.config import API_PREFIX
from app.core.db.session import get_db
from app.api.v1.dependencies.permissions import require_permission


# --- Dependency overrides ---

class AsyncSessionMock:
    async def execute(self, *args, **kwargs):
        return None
    async def commit(self): pass
    async def refresh(self, obj): pass
    async def delete(self, obj): pass

async def override_get_db():
    yield AsyncSessionMock()

# override require_permission which takes a permission name argument
def override_require_permission(permission_name):
    async def dummy_permission():
        return True
    return dummy_permission

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[require_permission] = override_require_permission


# --- Tests ---

@pytest.mark.asyncio
@patch("app.api.v1.services.user.UserService.create_user", new_callable=AsyncMock)
async def test_create_user(mock_create_user):
    now = datetime.utcnow()
    mock_create_user.return_value = {
        "id": 1,
        "first": "Test",
        "last": "User",
        "username": "testuser",
        "email": "test@example.com",
        "phone": None,
        "role_id": 2,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"{API_PREFIX}/users/",
            json={
                "first": "Test",
                "last": "User",
                "username": "testuser",
                "email": "test@example.com",
                "password": "pass123",
                "phone": None,
                "role_id": 2,
            },
        )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert data["first"] == "Test"
    mock_create_user.assert_awaited_once()


@pytest.mark.asyncio
@patch("app.api.v1.services.user.UserService.get_user", new_callable=AsyncMock)
async def test_get_user(mock_get_user):
    now = datetime.utcnow()
    mock_get_user.return_value = {
        "id": 1,
        "first": "Get",
        "last": "User",
        "username": "getuser",
        "email": "get@example.com",
        "phone": None,
        "role_id": 3,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"{API_PREFIX}/users/1")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "getuser"
    assert data["first"] == "Get"
    mock_get_user.assert_awaited_once_with(1, ANY)


@pytest.mark.asyncio
@patch("app.api.v1.services.user.UserService.get_user", new_callable=AsyncMock)
async def test_get_user_not_found(mock_get_user):
    mock_get_user.return_value = None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"{API_PREFIX}/users/9999")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found"
    mock_get_user.assert_awaited_once_with(9999, ANY)


@pytest.mark.asyncio
@patch("app.api.v1.services.user.UserService.get_all_users", new_callable=AsyncMock)
async def test_list_users(mock_get_all_users):
    now = datetime.utcnow()
    mock_get_all_users.return_value = [
        {
            "id": 1,
            "first": "First1",
            "last": "Last1",
            "username": "user1",
            "email": "user1@example.com",
            "phone": None,
            "role_id": 1,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        },
        {
            "id": 2,
            "first": "First2",
            "last": "Last2",
            "username": "user2",
            "email": "user2@example.com",
            "phone": None,
            "role_id": 2,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        },
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"{API_PREFIX}/users/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert data[0]["username"] == "user1"
    assert data[1]["email"] == "user2@example.com"
    mock_get_all_users.assert_awaited_once()

