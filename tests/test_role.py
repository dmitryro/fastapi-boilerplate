import pytest
from fastapi import status
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock
from app.main import app
from app.api.v1.security.jwt import get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
from app.api.v1.models.role import Role as RoleModel
from app.api.v1.services.role import RoleService # Import RoleService for direct service method testing
from app.api.v1.schemas.role import RoleCreate, RoleUpdate # Import schemas for service method testing
from datetime import datetime, timezone
from sqlalchemy.exc import SQLAlchemyError # Import SQLAlchemyError for testing exceptions
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
    async def inner(user: DummyUser = pytest.param(DummyUser(), _scope="session")): # Use pytest.param for dependency
        return user
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

# Service-level tests for app/api/v1/services/role.py
@pytest.mark.asyncio
async def test_service_get_all_roles():
    """Test RoleService.get_all_roles."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    expected_roles = [
        role_model_stub(id=1, name="role1"),
        role_model_stub(id=2, name="role2"),
    ]
    mock_scalar_result.all.return_value = expected_roles
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    roles = await RoleService.get_all_roles(db)
    assert len(roles) == 2
    assert roles[0].name == "role1"
    assert roles[1].name == "role2"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_role():
    """Test RoleService.get_role."""
    db = AsyncMock()
    mock_result = MagicMock()
    expected_role = role_model_stub(id=1, name="testrole")
    mock_result.scalar_one_or_none.return_value = expected_role
    db.execute.return_value = mock_result

    role = await RoleService.get_role(db, 1)
    assert role.id == 1
    assert role.name == "testrole"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_role_not_found():
    """Test RoleService.get_role when role is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    role = await RoleService.get_role(db, 999)
    assert role is None
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_role():
    """Test RoleService.create_role."""
    db = AsyncMock()
    role_in = RoleCreate(name="new_role", permissions=["perm1"])
    
    # Mock db.refresh to set an ID and update timestamps
    def refresh_side_effect(role_obj):
        role_obj.id = 1
        role_obj.created_at = datetime.now(timezone.utc)
        role_obj.updated_at = datetime.now(timezone.utc)
    db.refresh.side_effect = refresh_side_effect

    role = await RoleService.create_role(db, role_in)
    assert role.name == "new_role"
    assert "perm1" in role.permissions
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_role_db_commit_failure():
    """Test RoleService.create_role with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    role_in = RoleCreate(name="fail_role", permissions=[])
    db.commit.side_effect = SQLAlchemyError("Simulated commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated commit error"):
        await RoleService.create_role(db, role_in)
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_role_db_refresh_failure():
    """Test RoleService.create_role with db.refresh raising SQLAlchemyError."""
    db = AsyncMock()
    role_in = RoleCreate(name="fail_refresh_role", permissions=[])
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await RoleService.create_role(db, role_in)
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_role():
    """Test RoleService.update_role."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1, name="old_name", permissions=["old_perm"])
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result # For the get_role call inside update_role

    role_in = RoleUpdate(name="updated_name", permissions=["new_perm"])
    updated_role = await RoleService.update_role(db, 1, role_in)

    assert updated_role.name == "updated_name"
    assert "new_perm" in updated_role.permissions
    db.execute.assert_awaited_once() # For the get_role call
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_role_not_found():
    """Test RoleService.update_role when role is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result # For the get_role call

    role_in = RoleUpdate(name="nonexistent_update")
    updated_role = await RoleService.update_role(db, 999, role_in)
    assert updated_role is None
    db.execute.assert_awaited_once()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_role_db_commit_failure():
    """Test RoleService.update_role with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1, name="old_name")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result

    role_in = RoleUpdate(name="fail_commit")
    db.commit.side_effect = SQLAlchemyError("Simulated update commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated update commit error"):
        await RoleService.update_role(db, 1, role_in)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_role_db_refresh_failure():
    """Test RoleService.update_role with db.refresh raising SQLAlchemyError."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1, name="old_name")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result

    role_in = RoleUpdate(name="fail_refresh")
    db.refresh.side_effect = SQLAlchemyError("Simulated update refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated update refresh error"):
        await RoleService.update_role(db, 1, role_in)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_role():
    """Test RoleService.delete_role."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result # For the get_role call

    deleted = await RoleService.delete_role(db, 1)
    assert deleted is True
    db.execute.assert_awaited_once()
    db.delete.assert_called_once_with(existing_role)
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_role_not_found():
    """Test RoleService.delete_role when role is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result # For the get_role call

    deleted = await RoleService.delete_role(db, 999)
    assert deleted is False
    db.execute.assert_awaited_once()
    db.delete.assert_not_called()
    db.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_role_db_delete_failure():
    """Test RoleService.delete_role with db.delete raising SQLAlchemyError."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result

    db.delete.side_effect = SQLAlchemyError("Simulated delete error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete error"):
        await RoleService.delete_role(db, 1)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_role_db_commit_failure():
    """Test RoleService.delete_role with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_role = role_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_role
    db.execute.return_value = mock_result

    db.commit.side_effect = SQLAlchemyError("Simulated delete commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete commit error"):
        await RoleService.delete_role(db, 1)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_awaited_once()

# Route-level tests for app/api/v1/routes/role.py
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
async def test_update_nonexistent_role_route(async_client, monkeypatch):
    """Test update_role route when the role to update is not found (covers line 47 in role.py)."""
    async def mock_update_role(db, role_id, role_in):
        logger.debug("Mock update_role called (returns None)")
        return None # Simulate role not found in service

    monkeypatch.setattr("app.api.v1.services.role.RoleService.update_role", mock_update_role)

    logger.debug("Sending PUT request to /api/v1/roles/999 (nonexistent)")
    response = await async_client.put(
        "/api/v1/roles/999",
        json={"name": "nonexistent_role_update"},
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Role not found"

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

@pytest.mark.asyncio
async def test_delete_nonexistent_role_route(async_client, monkeypatch):
    """Test delete_role route when the role to delete is not found (covers line 58 in role.py)."""
    async def mock_delete_role(db, role_id):
        logger.debug("Mock delete_role called (returns False)")
        return False # Simulate role not found in service

    monkeypatch.setattr("app.api.v1.services.role.RoleService.delete_role", mock_delete_role)

    logger.debug("Sending DELETE request to /api/v1/roles/999 (nonexistent)")
    response = await async_client.delete(
        "/api/v1/roles/999",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Role not found"
