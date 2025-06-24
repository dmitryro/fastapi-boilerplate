import pytest
from fastapi import status
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from unittest.mock import AsyncMock, MagicMock
from app.main import app
from app.api.v1.security.jwt import get_current_user, require_permission
from app.core.db.session import get_db
from app.api.v1.models.user import User as UserModel
from app.api.v1.security.passwords import hash_password, verify_password
from app.api.v1.services.user import UserService
from app.api.v1.schemas.user import UserCreate, UserUpdate
from datetime import datetime, timezone
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError # Import SQLAlchemyError
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
    logger.debug(f"Dummy require permission called for: {permission}")
    async def inner(user: UserModel = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        logger.debug(f"Dummy permission check for: {permission}")
        return user
    return inner

# DB fixture with awaited async mocks
@pytest.fixture
async def async_client():
    # Override user and permission dependencies
    app.dependency_overrides[get_current_user] = dummy_get_current_user
    app.dependency_overrides[require_permission] = dummy_require_permission

    # Create an AsyncMock for DB session
    db = AsyncMock(spec=AsyncSession)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.add = AsyncMock()
    db.delete = AsyncMock()
    # Mock db.execute to return a MagicMock with proper scalars support
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRole()
    mock_scalar_result.all.return_value = []
    mock_result.scalars.return_value = mock_scalar_result
    mock_result.scalar_one_or_none.return_value = DummyRole()
    db.execute.return_value = mock_result

    async def mock_get_db():
        logger.debug("Mock get_db called")
        yield db

    app.dependency_overrides[get_db] = mock_get_db

    # Setup HTTPX client
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()

# User factory
def user_model_stub(**kwargs):
    user = UserModel(
        id=kwargs.get("id", 1),
        email=kwargs.get("email", "user@example.com"),
        username=kwargs.get("username", "user"),
        password=kwargs.get("password", "hashedpw"),
        role_id=kwargs.get("role_id", 2),
        first=kwargs.get("first", "First"),
        last=kwargs.get("last", "Last"),
        phone=kwargs.get("phone", None),
        created_at=kwargs.get("created_at", datetime.now(timezone.utc)),
        updated_at=kwargs.get("updated_at", datetime.now(timezone.utc)),
    )
    # REMOVED: Overrides of set_password and verify_password
    # user.set_password = lambda password: setattr(user, 'password', hash_password(password))
    # user.verify_password = lambda password: verify_password(user.password, password)
    return user

# Model-level tests
@pytest.mark.asyncio
async def test_user_password_methods():
    """Test User model's password hashing and verification methods."""
    user = user_model_stub()
    plain_password = "SecurePass123!"
    
    # Test set_password (now uses the actual UserModel.set_password)
    logger.debug("Testing set_password")
    user.set_password(plain_password)
    assert user.password != plain_password  # Password should be hashed
    assert user.password.startswith("$argon2id$")  # Verify Argon2 hash format
    
    # Test verify_password with correct password (now uses the actual UserModel.verify_password)
    logger.debug("Testing verify_password with correct password")
    assert user.verify_password(plain_password) is True
    
    # Test verify_password with incorrect password (now uses the actual UserModel.verify_password)
    logger.debug("Testing verify_password with incorrect password")
    assert user.verify_password("WrongPass123!") is False

# Service-level tests
@pytest.mark.asyncio
async def test_service_get_all_users():
    """Test UserService.get_all_users."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    expected_users = [
        user_model_stub(id=1, username="user1"),
        user_model_stub(id=2, username="user2"),
    ]
    mock_scalar_result.all.return_value = expected_users
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    users = await UserService.get_all_users(db)
    assert len(users) == 2
    assert users[0].username == "user1"
    assert users[1].username == "user2"
    db.execute.assert_awaited()

@pytest.mark.asyncio
async def test_service_get_user():
    """Test UserService.get_user."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    expected_user = user_model_stub(id=1, username="testuser")
    mock_result.scalar_one_or_none.return_value = expected_user
    db.execute.return_value = mock_result

    user = await UserService.get_user(db, 1)
    assert user.id == 1
    assert user.username == "testuser"
    db.execute.assert_awaited()

@pytest.mark.asyncio
async def test_service_get_user_not_found():
    """Test UserService.get_user when user is not found."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    user = await UserService.get_user(db, 999)
    assert user is None
    db.execute.assert_awaited()

@pytest.mark.asyncio
async def test_service_get_user_by_username():
    """Test UserService.get_user_by_username."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    expected_user = user_model_stub(username="testuser")
    mock_result.scalar_one_or_none.return_value = expected_user
    db.execute.return_value = mock_result

    user = await UserService.get_user_by_username(db, "testuser")
    assert user.username == "testuser"
    db.execute.assert_awaited()

@pytest.mark.asyncio
async def test_service_get_user_by_username_not_found():
    """Test UserService.get_user_by_username when user is not found."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    user = await UserService.get_user_by_username(db, "nonexistent")
    assert user is None
    db.execute.assert_awaited()

@pytest.mark.asyncio
async def test_service_create_user():
    """Test UserService.create_user."""
    db = AsyncMock(spec=AsyncSession)
    user_in = UserCreate(
        email="newuser@example.com",
        username="newuser",
        password="SecurePass123!",
        role_id=2,
        first="New",
        last="User",
    )
    # Mock the user creation to avoid actual DB interaction
    expected_user = user_model_stub(email=user_in.email, username=user_in.username)
    db.add.side_effect = lambda x: setattr(db, '_added_user', x)
    db.refresh.side_effect = lambda x: setattr(x, 'id', 1)

    user = await UserService.create_user(db, user_in)
    assert user.email == "newuser@example.com"
    assert user.username == "newuser"
    assert db._added_user.email == user_in.email
    db.add.assert_called()
    db.commit.assert_awaited()
    db.refresh.assert_awaited()

@pytest.mark.asyncio
async def test_service_create_user_db_commit_failure():
    """Test UserService.create_user with db.commit raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    user_in = UserCreate(
        email="failcommit@example.com", username="failcommit",
        password="SecurePass123!", role_id=2, first="Commit", last="Fail"
    )
    db.commit.side_effect = SQLAlchemyError("Simulated commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated commit error"):
        await UserService.create_user(db, user_in)
    
    db.add.assert_called_once() # User is added before commit attempt
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited() # Refresh should not be called if commit fails
    db.rollback.assert_not_awaited() # UserService does not explicitly rollback for this error

@pytest.mark.asyncio
async def test_service_create_user_db_refresh_failure():
    """Test UserService.create_user with db.refresh raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    user_in = UserCreate(
        email="failrefresh@example.com", username="failrefresh",
        password="SecurePass123!", role_id=2, first="Refresh", last="Fail"
    )
    # Ensure commit succeeds, then refresh fails
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await UserService.create_user(db, user_in)
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once() # Commit should have been called before refresh
    db.refresh.assert_awaited_once()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user():
    """Test UserService.update_user."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1, username="olduser")
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result

    user_in = UserUpdate(username="newuser", email="newuser@example.com")
    user = await UserService.update_user(db, 1, user_in)
    assert user.username == "newuser"
    assert user.email == "newuser@example.com"
    db.commit.assert_awaited()
    db.refresh.assert_awaited()

@pytest.mark.asyncio
async def test_service_update_user_db_commit_failure():
    """Test UserService.update_user with db.commit raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1, username="olduser")
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result # For get_user call
    
    db.commit.side_effect = SQLAlchemyError("Simulated update commit error")

    user_in = UserUpdate(username="newuser")
    with pytest.raises(SQLAlchemyError, match="Simulated update commit error"):
        await UserService.update_user(db, 1, user_in)
    
    db.execute.assert_awaited_once() # For get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_db_refresh_failure():
    """Test UserService.update_user with db.refresh raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1, username="olduser")
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result # For get_user call

    db.refresh.side_effect = SQLAlchemyError("Simulated update refresh error")

    user_in = UserUpdate(username="newuser")
    with pytest.raises(SQLAlchemyError, match="Simulated update refresh error"):
        await UserService.update_user(db, 1, user_in)
    
    db.execute.assert_awaited_once() # For get_user
    db.commit.assert_awaited_once() # Commit should have been called
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_user_not_found():
    """Test UserService.update_user when user is not found."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    user_in = UserUpdate(username="newuser")
    user = await UserService.update_user(db, 999, user_in)
    assert user is None
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_user():
    """Test UserService.delete_user."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1)
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result

    deleted = await UserService.delete_user(db, 1)
    assert deleted is True
    db.delete.assert_called_with(existing_user)
    db.commit.assert_awaited()

@pytest.mark.asyncio
async def test_service_delete_user_db_delete_failure():
    """Test UserService.delete_user with db.delete raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1)
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result # For get_user call

    db.delete.side_effect = SQLAlchemyError("Simulated delete error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete error"):
        await UserService.delete_user(db, 1)
    
    db.execute.assert_awaited_once() # For get_user
    db.delete.assert_called_once()
    db.commit.assert_not_awaited() # Commit should not be called if delete fails

@pytest.mark.asyncio
async def test_service_delete_user_db_commit_failure():
    """Test UserService.delete_user with db.commit raising SQLAlchemyError."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    existing_user = user_model_stub(id=1)
    mock_result.scalar_one_or_none.return_value = existing_user
    db.execute.return_value = mock_result # For get_user call

    db.commit.side_effect = SQLAlchemyError("Simulated delete commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete commit error"):
        await UserService.delete_user(db, 1)
    
    db.execute.assert_awaited_once() # For get_user
    db.delete.assert_called_once()
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_user_not_found():
    """Test UserService.delete_user when user is not found."""
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    deleted = await UserService.delete_user(db, 999)
    assert deleted is False
    db.delete.assert_not_called()
    db.commit.assert_not_awaited()

# Route-level tests
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
async def test_update_user_not_found(async_client, monkeypatch):
    async def mock_update_user(db, user_id, user_in):
        logger.debug("Mock update_user called")
        return None

    monkeypatch.setattr("app.api.v1.services.user.UserService.update_user", mock_update_user)

    logger.debug("Sending PUT request to /api/v1/users/999")
    response = await async_client.put(
        "/api/v1/users/999",
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
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found"

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

@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, monkeypatch):
    async def mock_delete_user(db, user_id):
        logger.debug("Mock delete_user called")
        return False

    monkeypatch.setattr("app.api.v1.services.user.UserService.delete_user", mock_delete_user)

    logger.debug("Sending DELETE request to /api/v1/users/999")
    response = await async_client.delete(
        "/api/v1/users/999",
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "User not found"

