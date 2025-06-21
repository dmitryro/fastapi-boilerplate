import pytest
from fastapi import status
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock
from app.main import app
from app.api.v1.security.jwt import get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
from app.api.v1.models.role import Role as RoleModel
from datetime import datetime, timezone
import logging

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy current user and role
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

# Role factory
def role_model_stub(**kwargs):
    return RoleModel(
        id=kwargs.get("id", 1),
        name=kwargs.get("name", "role"),
        permissions=kwargs.get("permissions", []),
        created_at=kwargs.get("created_at", datetime.now(timezone.utc))
    )

@pytest.mark.asyncio
async def test_create_role(async_client, monkeypatch):
    async def mock_create_role(db, role_in):
        logger.debug("Mock create_role called")
        return role_model_stub(name=role_in.name, permissions=role_in.permissions)

    monkeypatch.setattr("app.api.v1.services.role.RoleService.create_role", mock_create_role)

    logger.debug("Sending POST request to /api/v1/roles/")
    response = await async_client.post(
        "/api/v1/roles/",
        json={
            "name": "manager",
            "permissions": ["users:read", "users:write"]
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["name"] == "manager"
    assert data["permissions"] == ["users:read", "users:write"]

@pytest.mark.asyncio
async def test_get_role(async_client, monkeypatch):
    async def mock_get_role(db, role_id):
        logger.debug("Mock get_role called")
        return role_model_stub(id=role_id, name="admin", permissions=["all"])

    monkeypatch.setattr("app.api.v1.services.role.RoleService.get_role", mock_get_role)

    logger.debug("Sending GET request to /api/v1/roles/1")
    response = await async_client.get(
        "/api/v1/roles/1",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "admin"
    assert data["permissions"] == ["all"]

@pytest.mark.asyncio
async def test_get_nonexistent_role(async_client, monkeypatch):
    async def mock_get_role(db, role_id):
        logger.debug("Mock get_role called")
        return None

    monkeypatch.setattr("app.api.v1.services.role.RoleService.get_role", mock_get_role)

    logger.debug("Sending GET request to /api/v1/roles/999")
    response = await async_client.get(
        "/api/v1/roles/999",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Role not found"

@pytest.mark.asyncio
async def test_list_roles(async_client, monkeypatch):
    async def mock_get_all_roles(db):
        logger.debug("Mock get_all_roles called")
        return [
            role_model_stub(id=1, name="admin", permissions=["all"]),
            role_model_stub(id=2, name="editor", permissions=["users:read", "users:write"])
        ]

    monkeypatch.setattr("app.api.v1.services.role.RoleService.get_all_roles", mock_get_all_roles)

    logger.debug("Sending GET request to /api/v1/roles/")
    response = await async_client.get(
        "/api/v1/roles/",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["name"] == "admin"
    assert data[1]["name"] == "editor"

@pytest.mark.asyncio
async def test_update_role(async_client, monkeypatch):
    async def mock_update_role(db, role_id, role_in):
        logger.debug("Mock update_role called")
        return role_model_stub(id=role_id, name="superadmin", permissions=["users:read", "users:write", "roles:read", "roles:write"])

    monkeypatch.setattr("app.api.v1.services.role.RoleService.update_role", mock_update_role)

    logger.debug("Sending PUT request to /api/v1/roles/1")
    response = await async_client.put(
        "/api/v1/roles/1",
        json={
            "name": "superadmin",
            "permissions": ["users:read", "users:write", "roles:read", "roles:write"]
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["name"] == "superadmin"
    assert data["permissions"] == ["users:read", "users:write", "roles:read", "roles:write"]

@pytest.mark.asyncio
async def test_delete_role(async_client, monkeypatch):
    async def mock_delete_role(db, role_id):
        logger.debug("Mock delete_role called")
        return True

    monkeypatch.setattr("app.api.v1.services.role.RoleService.delete_role", mock_delete_role)

    logger.debug("Sending DELETE request to /api/v1/roles/1")
    response = await async_client.delete(
        "/api/v1/roles/1",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.text}")
    assert response.status_code == status.HTTP_204_NO_CONTENT
