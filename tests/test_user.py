import pytest
from fastapi import status
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock
from app.main import app
from app.api.v1.security.jwt import get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
from app.api.v1.models.user import User as UserModel
from datetime import datetime, timezone
import logging

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy current user and permission
class DummyUser:
    id = 1
    username = "admin"
    role_id = 1

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

# Async dummy current user
async def dummy_get_current_user():
    logger.debug("Dummy get_current_user called")
    return DummyUser()

# Async dummy permission checker
def dummy_require_permission(permission: str):
    logger.debug(f"Require permission called for: {permission}")
    async def inner():
        return DummyUser()
    return inner

# DB fixture with awaited async mocks
@pytest.fixture
async def async_client():
    # Override user and permission dependencies
    app.dependency_overrides[get_current_user] = dummy_get_current_user
    app.dependency_overrides[require_permission] = dummy_require_permission

    # Create an AsyncMock for DB session
    db = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.add = AsyncMock()
    db.delete = AsyncMock()
    # Mock db.execute to return a Result object
    db.execute = AsyncMock(return_value=type('Result', (), {
        'scalars': lambda *args, **kwargs: type('Scalars', (), {
            'first': lambda *args, **kwargs: DummyRole(),
            'all': lambda *args, **kwargs: []
        })(),
        'scalar_one_or_none': lambda *args, **kwargs: DummyRole()
    })())

    async def mock_get_db():
        logger.debug("Mock get_db called")
        yield db

    app.dependency_overrides[get_db] = mock_get_db

    # Setup HTTPX client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()

# User factory
def user_model_stub(**kwargs):
    return UserModel(
        id=kwargs.get("id", 1),
        email=kwargs.get("email", "user@example.com"),
        username=kwargs.get("username", "user"),
        password="hashedpw",
        role_id=kwargs.get("role_id", 2),
        first=kwargs.get("first", "First"),
        last=kwargs.get("last", "Last"),
        phone=kwargs.get("phone", None),
        created_at=kwargs.get("created_at", datetime.now(timezone.utc)),
        updated_at=kwargs.get("updated_at", datetime.now(timezone.utc)),
    )

@pytest.mark.asyncio
async def test_create_user(async_client, monkeypatch):
    async def mock_create_user(db, user_in):
        logger.debug("Mock create_user called")
        return user_model_stub(email=user_in.email, username=user_in.username)

    monkeypatch.setattr("app.api.v1.services.user.UserService.create_user", mock_create_user)

    logger.debug("Sending POST request to /api/v1/users/")
    response = await async_client.post(
        "/api/v1/users/",
        json={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "SecurePass123!",
            "role_id": 2,
            "first": "New",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["username"] == "newuser"

@pytest.mark.asyncio
async def test_get_user(async_client, monkeypatch):
    async def mock_get_user(db, user_id):
        logger.debug("Mock get_user called")
        return user_model_stub(id=user_id, username="existinguser")

    monkeypatch.setattr("app.api.v1.services.user.UserService.get_user", mock_get_user)

    logger.debug("Sending GET request to /api/v1/users/1")
    response = await async_client.get(
        "/api/v1/users/1",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "existinguser"

@pytest.mark.asyncio
async def test_get_user_not_found(async_client, monkeypatch):
    async def mock_get_user(db, user_id):
        logger.debug("Mock get_user called")
        return None

    monkeypatch.setattr("app.api.v1.services.user.UserService.get_user", mock_get_user)

    logger.debug("Sending GET request to /api/v1/users/999")
    response = await async_client.get(
        "/api/v1/users/999",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_list_users(async_client, monkeypatch):
    async def mock_get_all_users(db):
        logger.debug("Mock get_all_users called")
        return [
            user_model_stub(id=1, username="user1", email="user1@example.com"),
            user_model_stub(id=2, username="user2", email="user2@example.com"),
        ]

    monkeypatch.setattr("app.api.v1.services.user.UserService.get_all_users", mock_get_all_users)

    logger.debug("Sending GET request to /api/v1/users/")
    response = await async_client.get(
        "/api/v1/users/",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2

@pytest.mark.asyncio
async def test_update_user(async_client, monkeypatch):
    async def mock_update_user(db, user_id, user_in):
        logger.debug("Mock update_user called")
        return user_model_stub(id=user_id, username="updateduser", email="updated@example.com")

    monkeypatch.setattr("app.api.v1.services.user.UserService.update_user", mock_update_user)

    logger.debug("Sending PUT request to /api/v1/users/1")
    response = await async_client.put(
        "/api/v1/users/1",
        json={
            "email": "updated@example.com",
            "username": "updateduser",
            "role_id": 2,
            "first": "Updated",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "updateduser"

@pytest.mark.asyncio
async def test_delete_user(async_client, monkeypatch):
    async def mock_delete_user(db, user_id):
        logger.debug("Mock delete_user called")
        return True

    monkeypatch.setattr("app.api.v1.services.user.UserService.delete_user", mock_delete_user)

    logger.debug("Sending DELETE request to /api/v1/users/1")
    response = await async_client.delete(
        "/api/v1/users/1",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.text}")
    assert response.status_code == status.HTTP_204_NO_CONTENT
