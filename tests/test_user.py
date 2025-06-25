import pytest
from fastapi import HTTPException, status # Import status for HTTP status codes
from httpx import AsyncClient
from httpx import ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch # Import patch for monkeypatching functions
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from app.core.db.session import get_db
from app.api.v1.services.user import UserService
from app.api.v1.schemas.user import User, UserCreate, UserUpdate
from app.api.v1.models.user import User as UserModel # Explicitly import UserModel
from app.api.v1.models.role import Role # Explicitly import Role
# These are imported by UserService, but User MODEL uses its own ph instance
from app.api.v1.security.jwt import get_current_user
from app.api.v1.security.passwords import hash_password, verify_password 
import app.main  # Adjust if your FastAPI app is imported differently
from app.main import app
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
async def async_client(monkeypatch):
    # Set up the mock DB session
    db_session = AsyncMock()
    # Permission dependency needs to see an admin or role with "read"
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result

    # Patch UserService.get_all_users to return DummyUser
    monkeypatch.setattr(UserService, "get_all_users", AsyncMock(return_value=[DummyUser()]))

    # get_db override as async generator (CRITICAL)
    async def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db

    # get_current_user override (CRITICAL)
    async def override_get_current_user():
        return DummyUser()
    app.dependency_overrides[get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides = {}

# --- Dummy Classes to mock User and Role models for tests ---
class DummyUser:
    """A dummy class to represent a User for general mocking purposes."""
    def __init__(self, id=1, username="admin_user", email="admin@example.com", role_id=1, is_active=True, is_superuser=False, first="First", last="Last", phone=None):
        self.id = id
        self.username = username
        self.email = email
        self.role_id = role_id
        self.is_active = is_active
        self.is_superuser = is_superuser
        self.first = first
        self.last = last
        self.phone = phone
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.role = None 
        # Add _sa_instance_state to mimic SQLAlchemy ORM objects
        self._sa_instance_state = MagicMock()

class DummyRole:
    """A dummy class to represent a Role model in tests."""
    def __init__(self, id=1, name="admin", permissions=["create", "read", "update", "delete"]):
        self.id = id
        self.name = name
        self.permissions = permissions if permissions is not None else []
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        # Add _sa_instance_state to mimic SQLAlchemy ORM objects
        self._sa_instance_state = MagicMock()
        
# --- Fixtures ---

@pytest.fixture
def override_get_current_user():
    async def _override(*args, **kwargs):
        return DummyUser()
    return _override


@pytest.fixture
async def async_db_session():
    """Provides a mocked AsyncSession for database interactions."""
    session = AsyncMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock() # db.add is synchronous
    session.delete = AsyncMock()
    session.execute = AsyncMock() # Main mock for execute, side_effect will be set per test

    yield session

# User factory
def user_model_stub(**kwargs):
    """
    Helper to create a UserModel instance for mocking purposes.
    Ensures password hashing and includes a mocked 'role' attribute.
    """
    user = UserModel(
        id=kwargs.get("id", 1),
        email=kwargs.get("email", "user@example.com"),
        username=kwargs.get("username", "user"),
        # Use a simple hashed value for tests. Real hash_password will be mocked.
        password=kwargs.get("password", "mocked_hashed_password"), 
        role_id=kwargs.get("role_id", 2),
        first=kwargs.get("first", "First"),
        last=kwargs.get("last", "Last"),
        phone=kwargs.get("phone", None),
        created_at=kwargs.get("created_at", datetime.now(timezone.utc).replace(tzinfo=None)),
        updated_at=kwargs.get("updated_at", datetime.now(timezone.utc).replace(tzinfo=None)),
    )
    # Manually attach a DummyRole instance to simulate the relationship loading
    # Assume default role for a stub is 'user' unless specified
    user.role = DummyRole(id=user.role_id, name=f"role_{user.role_id}", 
                          permissions=["*"] if user.role_id == 1 else ["users:read"])
    return user

# Helper to create a mock result for db.execute that correctly supports scalars() and scalar_one_or_none()
def mock_execute_result_factory(scalar_one_or_none_value=None, scalars_all_value=None):
    """
    Returns a MagicMock object that mimics the result of await db.execute().
    This object will have .scalars() and .scalar_one_or_none() methods.
    """
    mock_result_obj = MagicMock()

    # Mock .scalars()
    mock_scalars_obj = MagicMock()
    mock_scalars_obj.all.return_value = scalars_all_value if scalars_all_value is not None else []
    mock_scalars_obj.first.return_value = scalars_all_value[0] if scalars_all_value else None
    mock_result_obj.scalars.return_value = mock_scalars_obj

    # Mock .scalar_one_or_none()
    mock_result_obj.scalar_one_or_none.return_value = scalar_one_or_none_value

    return mock_result_obj


# --- Tests for UserService.create_user ---

@pytest.mark.asyncio
async def test_service_create_user(async_db_session, monkeypatch):
    """Test UserService.create_user with valid data (success path)."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com",
        username="newuser",
        password="SecurePass123!",
        role_id=2, # Using DummyRole.id = 2
        first="New",
        last="User",
    )
    
    # Mock hash_password to return a consistent value by patching where it's used by UserService
    mock_hashed_password_value = "mocked_hashed_password"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_password_value))

    # Configure db.execute.side_effect for the sequence of validator calls:
    # 1. ensure_unique_email: returns None (email is unique)
    # 2. ensure_unique_username: returns None (username is unique)
    # 3. ensure_valid_role_id: returns a DummyRole (role_id is valid)
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # For email uniqueness check
        mock_execute_result_factory(scalar_one_or_none_value=None), # For username uniqueness check
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # For role existence check
    ]

    # Mock db.refresh to simulate a DB-assigned ID and updated timestamps
    def refresh_side_effect(user_obj):
        user_obj.id = 1 # Simulate ID assigned by DB
        user_obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        # Ensure the password attribute on the user object is set to the mocked string value
        user_obj.password = mock_hashed_password_value 
        # Attach the dummy role to the user object, as the service typically does this
        user_obj.role = DummyRole(id=user_obj.role_id, name="user")
    db.refresh.side_effect = refresh_side_effect

    user = await UserService.create_user(db, user_in)
    assert user.email == "newuser@example.com"
    assert user.username == "newuser"
    assert user.id == 1 # Assert the ID set by refresh_side_effect
    assert user.password == mock_hashed_password_value # Verify password was set to mocked hash
    
    db.add.assert_called_once() # Ensure user object was added to session
    db.commit.assert_awaited_once() # Ensure transaction was committed
    db.refresh.assert_awaited_once_with(user) # Ensure user object was refreshed
    assert db.execute.call_count == 3 # All three validator checks were performed
    db.rollback.assert_not_awaited() # No rollback on success


@pytest.mark.asyncio
async def test_service_create_user_email_already_in_use(async_db_session):
    """Test UserService.create_user when email is already in use."""
    db = async_db_session
    user_in = UserCreate(
        email="existing@example.com", username="newuser",
        password="SecurePass123!", role_id=2, first="New", last="User"
    )
    
    # Simulate existing user for email check
    db.execute.return_value = mock_execute_result_factory(
        scalar_one_or_none_value=user_model_stub(email="existing@example.com")
    )

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Email already in use."
    db.execute.assert_awaited_once() # Only email check
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_username_already_taken(async_db_session):
    """Test UserService.create_user when username is already taken."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="existinguser",
        password="SecurePass123!", role_id=2, first="New", last="User"
    )
    
    # Simulate email being unique, but username existing
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=user_model_stub(username="existinguser")), # Username uniqueness check fails
    ]

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Username already taken."
    assert db.execute.call_count == 2 # Email and username checks
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_invalid_role_id(async_db_session):
    """Test UserService.create_user when role_id is invalid."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="newuser",
        password="SecurePass123!", role_id=999, first="New", last="User"
    )
    
    # Simulate email and username being unique, but role_id being invalid
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Role existence check fails (no role found)
    ]

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Role with ID 999 not found."
    assert db.execute.call_count == 3 # Email, username, and role checks
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_weak_password(async_db_session, monkeypatch):
    """Test UserService.create_user with a weak password."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="newuser",
        password="weak", # Too short password
        role_id=2, first="New", last="User"
    )

    # Mock hash_password but ensure it's not called if validation fails early.
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value="mocked_hashed_password"))
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "password" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower() # More general assertion

    assert db.execute.call_count == 3 # All DB-related validations pass before password check
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_create_user_short_username(async_db_session):
    """Test UserService.create_user with a too-short username."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="nu", # Too short username
        password="SecurePass123!", role_id=2, first="New", last="User"
    )
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]
    
    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "username" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    assert db.execute.call_count == 3 
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_short_first_name(async_db_session):
    """Test UserService.create_user with a too-short first name."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="newuser",
        password="SecurePass123!", role_id=2, first="N", # Too short first name
        last="User"
    )
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "first name" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    assert db.execute.call_count == 3
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_short_last_name(async_db_session):
    """Test UserService.create_user with a too-short last name."""
    db = async_db_session
    user_in = UserCreate(
        email="newuser@example.com", username="newuser",
        password="SecurePass123!", role_id=2, first="New", 
        last="U" # Too short last name
    )
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]

    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "last name" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    assert db.execute.call_count == 3
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_create_user_db_commit_failure(async_db_session, monkeypatch):
    """Test UserService.create_user with db.commit raising an Exception and causing rollback."""
    db = async_db_session
    user_in = UserCreate(
        email="failcommit@example.com", username="failcommit",
        password="SecurePass123!", role_id=2, first="Commit", last="Fail"
    )
    
    mock_hashed_password_value = "mocked_hashed_password"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_password_value))

    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]
    db.commit.side_effect = SQLAlchemyError("Simulated commit error") # Use SQLAlchemyError for DB-related errors

    with pytest.raises(HTTPException) as exc_info: # Expect HTTPException from UserService
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Failed to create user due to a database error: Simulated commit error" in exc_info.value.detail
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited() # Refresh should not be called after commit failure
    db.rollback.assert_awaited_once() # Rollback should be called on commit failure

@pytest.mark.asyncio
async def test_service_create_user_db_refresh_failure(async_db_session, monkeypatch):
    """Test UserService.create_user with db.refresh raising an Exception and causing rollback."""
    db = async_db_session
    user_in = UserCreate(
        email="failrefresh@example.com", username="failrefresh",
        password="SecurePass123!", role_id=2, first="Refresh", last="Fail"
    )
    
    mock_hashed_password_value = "mocked_hashed_password"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_password_value))

    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check passes
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=2, name="user")), # Role existence check passes
    ]
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error") # Use SQLAlchemyError for DB-related errors

    with pytest.raises(HTTPException) as exc_info: # Expect HTTPException from UserService
        await UserService.create_user(db, user_in)
    
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Failed to create user due to a database error: Simulated refresh error" in exc_info.value.detail
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once() # Refresh should be called, then it fails
    db.rollback.assert_awaited_once() # Rollback should be called on refresh failure


# --- Tests for UserService.get_all_users ---

@pytest.mark.asyncio
async def test_service_get_all_users(async_db_session):
    """Test UserService.get_all_users returns a list of users."""
    db = async_db_session
    expected_users = [
        user_model_stub(id=1, username="user1", email="user1@example.com"),
        user_model_stub(id=2, username="user2", email="user2@example.com"),
    ]
    db.execute.return_value = mock_execute_result_factory(scalars_all_value=expected_users)

    users = await UserService.get_all_users(db)
    assert len(users) == 2
    assert users[0].username == "user1"
    assert users[1].username == "user2"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_all_users_empty(async_db_session):
    """Test UserService.get_all_users returns an empty list if no users found."""
    db = async_db_session
    db.execute.return_value = mock_execute_result_factory(scalars_all_value=[]) # Empty list

    users = await UserService.get_all_users(db)
    assert len(users) == 0
    assert users == []
    db.execute.assert_awaited_once()


# --- Tests for UserService.get_user (by ID) ---

@pytest.mark.asyncio
async def test_service_get_user_success(async_db_session):
    """Test UserService.get_user returns a user by ID."""
    db = async_db_session
    expected_user = user_model_stub(id=1, username="founduser")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=expected_user)

    user = await UserService.get_user(db, 1)
    assert user.id == 1
    assert user.username == "founduser"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_user_not_found(async_db_session):
    """Test UserService.get_user returns None if user not found by ID."""
    db = async_db_session
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=None)

    user = await UserService.get_user(db, 999)
    assert user is None
    db.execute.assert_awaited_once()


# --- Tests for UserService.get_user_by_username ---

@pytest.mark.asyncio
async def test_service_get_user_by_username_success(async_db_session):
    """Test UserService.get_user_by_username returns a user by username."""
    db = async_db_session
    expected_user = user_model_stub(username="foundbyname")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=expected_user)

    user = await UserService.get_user_by_username(db, "foundbyname")
    assert user.username == "foundbyname"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_user_by_username_not_found(async_db_session):
    """Test UserService.get_user_by_username returns None if user not found by username."""
    db = async_db_session
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=None)

    user = await UserService.get_user_by_username(db, "nonexistent")
    assert user is None
    db.execute.assert_awaited_once()


# --- Tests for UserService.update_user ---

@pytest.mark.asyncio
async def test_service_update_user_success(async_db_session, monkeypatch):
    """Test UserService.update_user with successful update of multiple fields."""
    db = async_db_session
    existing_user_id = 1
    # Create an existing user mock for the initial lookup
    existing_user = user_model_stub(id=existing_user_id, username="olduser", email="old@example.com", role_id=2)

    user_in = UserUpdate(
        username="newuser",
        email="new@example.com",
        role_id=1, # Change role to admin (DummyRole with id=1 implicitly has '*' permissions)
        first="Updated",
        last="User", 
        password="NewSecurePass123!"
    )

    # Mock hash_password for the update operation if password is provided
    mock_hashed_new_password_value = "mocked_hashed_new_password"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_new_password_value))

    # Configure side_effect for db.execute for sequence of calls in update_user:
    # 1. Initial `get_user` by ID: returns `existing_user`
    # 2. `ensure_unique_email`: returns `None` (new email is unique)
    # 3. `ensure_unique_username`: returns `None` (new username is unique)
    # 4. `ensure_valid_role_id`: returns `DummyRole(id=1)` (new role exists)
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # For initial UserService.get_user
        mock_execute_result_factory(scalar_one_or_none_value=None),          # For ensure_unique_email
        mock_execute_result_factory(scalar_one_or_none_value=None),          # For ensure_unique_username
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=1, name="admin")), # For ensure_valid_role_id
    ]

    # Mock db.refresh behavior to simulate updates on the `existing_user` object
    def update_refresh_side_effect(user_obj):
        # Apply the updates that the service is expected to perform
        user_obj.username = user_in.username
        user_obj.email = user_in.email
        user_obj.role_id = user_in.role_id
        user_obj.first = user_in.first
        user_obj.last = user_in.last
        user_obj.password = mock_hashed_new_password_value # Set to the mocked hashed password string
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None) # Update timestamp
        user_obj.role = DummyRole(id=user_obj.role_id, name="admin")
    db.refresh.side_effect = update_refresh_side_effect

    user = await UserService.update_user(db, existing_user_id, user_in)
    
    assert user is not None
    assert user.id == existing_user_id
    assert user.username == "newuser"
    assert user.email == "new@example.com"
    assert user.role_id == 1 # Verify updated role ID
    assert user.first == "Updated"
    assert user.last == "User" 
    assert user.password == mock_hashed_new_password_value # Verify new password is set
    
    assert db.execute.call_count == 4 # Initial get_user + 3 validator checks
    db.commit.assert_awaited_once() # Ensure transaction was committed
    db.refresh.assert_awaited_once_with(existing_user) # Ensure the existing user object was refreshed
    db.rollback.assert_not_awaited() # No rollback on success

@pytest.mark.asyncio
async def test_service_update_user_not_found(async_db_session):
    """Test UserService.update_user when the user to be updated is not found."""
    db = async_db_session
    user_id = 999
    
    # Initial `get_user` by ID returns None
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=None)

    user_in = UserUpdate(username="newuser", email="new@example.com") 
    user = await UserService.update_user(db, user_id, user_in)
    
    assert user is None # Expect None if user not found
    
    db.execute.assert_awaited_once() # Only the initial get_user call
    db.commit.assert_not_awaited() 
    db.refresh.assert_not_awaited() 
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_no_changes(async_db_session):
    """Test UserService.update_user when no fields are updated (empty UserUpdate)."""
    db = async_db_session
    existing_user_id = 1
    existing_user = user_model_stub(id=existing_user_id, username="olduser", email="old@example.com")
    
    # Initial `get_user` by ID returns the existing user
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    # Mock db.refresh behavior (still called to update `updated_at` even if no other fields change)
    def update_refresh_side_effect(user_obj):
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate() # Empty UserUpdate object
    user = await UserService.update_user(db, existing_user_id, user_in)
    
    assert user is not None
    assert user.id == existing_user_id
    assert user.username == "olduser" # Should remain unchanged
    
    db.execute.assert_awaited_once() # Only the initial get_user call
    db.commit.assert_awaited_once() # Commit is still called even if no fields changed (due to updated_at)
    db.refresh.assert_awaited_once_with(existing_user) # Refresh is still called
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_same_username(async_db_session):
    """
    Test UserService.update_user when username is provided but is the same as current.
    Should not raise an exception, but succeed.
    """
    db = async_db_session
    existing_user_id = 1
    existing_user_username = "currentuser"
    existing_user = user_model_stub(id=existing_user_id, username=existing_user_username, email="current@example.com")
    
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(username=existing_user_username) # Username is explicitly set but same
    
    user = await UserService.update_user(db, existing_user_id, user_in)
        
    assert user is not None
    assert user.username == existing_user_username # Username should remain unchanged
    
    assert db.execute.call_count == 1 # Only the initial get_user call as username is same. No uniqueness check.
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_same_email(async_db_session):
    """
    Test UserService.update_user when email is provided but is the same as current.
    Should not raise an exception, but succeed.
    """
    db = async_db_session
    existing_user_id = 1
    existing_user_email = "current@example.com"
    existing_user = user_model_stub(id=existing_user_id, username="currentuser", email=existing_user_email)
    
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(email=existing_user_email) # Email is explicitly set but same
    
    user = await UserService.update_user(db, existing_user_id, user_in)
        
    assert user is not None
    assert user.email == existing_user_email # Email should remain unchanged
    
    assert db.execute.call_count == 1 # Only the initial get_user call as email is same. No uniqueness check.
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_same_role_id(async_db_session):
    """Test UserService.update_user when role_id is provided but is the same as current."""
    db = async_db_session
    existing_user_id = 1
    existing_user_role_id = 2
    existing_user = user_model_stub(id=existing_user_id, username="currentuser", email="current@example.com", role_id=existing_user_role_id)
    
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(role_id=existing_user_role_id) # Role ID is explicitly set but same
    user = await UserService.update_user(db, existing_user_id, user_in)
    
    assert user is not None
    assert user.role_id == existing_user_role_id # Role ID should remain unchanged
    
    assert db.execute.call_count == 1 # Only the initial get_user call as role_id is same. No role existence check.
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_update_user_short_username(async_db_session):
    """Test UserService.update_user with a too-short username."""
    db = async_db_session
    existing_user = user_model_stub(id=1, username="olduser")
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness check (passes if no conflict)
    ]
    
    user_in = UserUpdate(username="nu") # Too short
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "username" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    assert db.execute.call_count == 2 # Initial get_user + username uniqueness check
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_short_first_name(async_db_session):
    """Test UserService.update_user with a too-short first name."""
    db = async_db_session
    existing_user = user_model_stub(id=1, first="Old")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)
    user_in = UserUpdate(first="N") # Too short
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "first name" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    db.execute.assert_awaited_once() # Only initial get_user, as name validation might happen before uniqueness checks
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_short_last_name(async_db_session):
    """Test UserService.update_user with a too-short last name."""
    db = async_db_session
    existing_user = user_model_stub(id=1, last="User")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)
    user_in = UserUpdate(last="U") # Too short
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "last name" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    db.execute.assert_awaited_once() # Only initial get_user
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_weak_password(async_db_session):
    """Test UserService.update_user with a weak password."""
    db = async_db_session
    existing_user = user_model_stub(id=1)
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)
    user_in = UserUpdate(password="weak") # Too weak
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "password" in exc_info.value.detail.lower() or "too short" in exc_info.value.detail.lower()
    db.execute.assert_awaited_once() # Only initial get_user
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_email_already_in_use(async_db_session):
    """Test UserService.update_user when new email is already in use by another user."""
    db = async_db_session
    existing_user = user_model_stub(id=1, email="old@example.com")
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        mock_execute_result_factory(scalar_one_or_none_value=user_model_stub(id=2, email="taken@example.com")) # Email uniqueness check fails (another user found)
    ]
    user_in = UserUpdate(email="taken@example.com")
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Email already in use."
    assert db.execute.call_count == 2 # Initial get_user + email uniqueness check
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_username_already_taken(async_db_session):
    """Test UserService.update_user when new username is already taken by another user."""
    db = async_db_session
    existing_user = user_model_stub(id=1, username="olduser", email="original@example.com") 
    
    # Only two side effects needed for this streamlined test case:
    # 1. Initial get_user
    # 2. Username uniqueness check (simulates finding a duplicate)
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        mock_execute_result_factory(scalar_one_or_none_value=user_model_stub(id=2, username="takenuser", email="taken@example.com")) # Username uniqueness check fails
    ]
    # Set user_in to only update the username to isolate this test
    user_in = UserUpdate(username="takenuser") 
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Username already taken."
    assert db.execute.call_count == 2 # Initial get_user + username uniqueness check
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_invalid_role_id(async_db_session):
    """Test UserService.update_user when the new role_id is invalid (not found in DB)."""
    db = async_db_session
    existing_user = user_model_stub(id=1, role_id=2, username="existinguser", email="existing@example.com") 
    
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        # Email and username are not provided in UserUpdate, so their uniqueness checks are skipped.
        # Only the role validity check should be performed after the initial get.
        mock_execute_result_factory(scalar_one_or_none_value=None) # Role validity check (new role_id 999 not found)
    ]
    user_in = UserUpdate(role_id=999) # Invalid role ID
    with pytest.raises(HTTPException) as exc_info:
        await UserService.update_user(db, 1, user_in)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Role with ID 999 not found."
    # Expect 2 calls: 1 for get_user, 1 for role validity check.
    assert db.execute.call_count == 2 
    db.commit.assert_not_awaited()
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_db_commit_failure(async_db_session, monkeypatch):
    """Test UserService.update_user with db.commit raising SQLAlchemyError."""
    db = async_db_session
    # Prepare existing user and update data
    existing_user = user_model_stub(id=1, username="olduser", email="old@example.com", role_id=2)
    user_in = UserUpdate(username="newuser", email="new@example.com", role_id=1) 
    
    # Mock hash_password if it's called
    mock_hashed_new_password_value = "mocked_hash"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_new_password_value))

    # Configure db.execute side effects for the sequence of operations
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness (passes)
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness (passes)
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=1, name="admin")) # Role validity (passes)
    ]
    
    db.commit.side_effect = SQLAlchemyError("Simulated update commit error")

    with pytest.raises(HTTPException, match="Failed to update user due to a database error: Simulated update commit error"):
        await UserService.update_user(db, 1, user_in)
    
    # Corrected assertion back to 4 based on expected calls for all fields updated
    assert db.execute.call_count == 4 
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited() # Should not be refreshed if commit fails
    db.rollback.assert_awaited_once() # Should rollback on commit failure

@pytest.mark.asyncio
async def test_service_update_user_db_refresh_failure(async_db_session, monkeypatch):
    """Test UserService.update_user with db.refresh raising SQLAlchemyError."""
    db = async_db_session
    # Prepare existing user and update data
    existing_user = user_model_stub(id=1, username="olduser", email="old@example.com", role_id=2)
    user_in = UserUpdate(username="newuser", email="new@example.com", role_id=1) 
    
    # Mock hash_password if it's called
    mock_hashed_new_password_value = "mocked_hash"
    monkeypatch.setattr("app.api.v1.services.user.hash_password", AsyncMock(return_value=mock_hashed_new_password_value))

    # Configure db.execute side effects for the sequence of operations
    db.execute.side_effect = [
        mock_execute_result_factory(scalar_one_or_none_value=existing_user), # Initial get_user
        mock_execute_result_factory(scalar_one_or_none_value=None), # Email uniqueness (passes)
        mock_execute_result_factory(scalar_one_or_none_value=None), # Username uniqueness (passes)
        mock_execute_result_factory(scalar_one_or_none_value=DummyRole(id=1, name="admin")) # Role validity (passes)
    ]
    
    db.refresh.side_effect = SQLAlchemyError("Simulated update refresh error")

    with pytest.raises(HTTPException, match="Failed to update user due to a database error: Simulated update refresh error"):
        await UserService.update_user(db, 1, user_in)
    
    # Corrected assertion back to 4 based on expected calls for all fields updated
    assert db.execute.call_count == 4 
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once() # Refresh should be called, then it fails
    db.rollback.assert_awaited_once() # Should rollback on refresh failure


# --- Tests for UserService.delete_user ---

@pytest.mark.asyncio
async def test_service_delete_user_success(async_db_session):
    """Test UserService.delete_user successfully deletes a user."""
    db = async_db_session
    existing_user = user_model_stub(id=1, username="todelete")
    
    # Initial `get_user` by ID returns the user to be deleted
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)
    
    deleted_user = await UserService.delete_user(db, 1)
    
    assert deleted_user is True # Expect True on successful deletion
    db.execute.assert_awaited_once() # For the initial get_user
    db.delete.assert_called_once_with(existing_user) # Ensure delete was called with the correct object
    db.commit.assert_awaited_once() # Ensure transaction was committed
    db.rollback.assert_not_awaited() # No rollback on success

@pytest.mark.asyncio
async def test_service_delete_user_not_found(async_db_session):
    """Test UserService.delete_user returns False if user to be deleted is not found."""
    db = async_db_session
    
    # Initial `get_user` by ID returns None
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=None)
    
    deleted = await UserService.delete_user(db, 999)
    
    assert deleted is False # Expect False if user not found
    db.execute.assert_awaited_once() # For the initial get_user
    db.delete.assert_not_called() # Delete should not be called if user not found
    db.commit.assert_not_awaited() 
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_user_db_commit_failure(async_db_session):
    """Test UserService.delete_user with db.commit raising SQLAlchemyError."""
    db = async_db_session
    existing_user = user_model_stub(id=1, username="todelete")
    
    # Initial `get_user` returns the user
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)
    db.commit.side_effect = SQLAlchemyError("Simulated delete commit error") 
    
    with pytest.raises(HTTPException, match="Failed to delete user due to a database error: Simulated delete commit error"):
        await UserService.delete_user(db, 1)
    
    db.execute.assert_awaited_once() # For the initial get_user
    db.delete.assert_called_once_with(existing_user) # Delete should still be called before commit
    db.commit.assert_awaited_once() # Commit is called, then fails
    db.rollback.assert_awaited_once() # Rollback should occur on commit failure


# --- Additional Tests for UserService.update_user (Single Field Updates & Nulling) ---

@pytest.mark.asyncio
async def test_service_update_user_only_first_name(async_db_session):
    """Test UserService.update_user when only first_name is changed."""
    db = async_db_session
    existing_user = user_model_stub(id=1, first="OldFirst")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.first = "NewFirst"
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(first="NewFirst")
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.first == "NewFirst"
    assert db.execute.call_count == 1 # Only initial get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_only_last_name(async_db_session):
    """Test UserService.update_user when only last_name is changed."""
    db = async_db_session
    existing_user = user_model_stub(id=1, last="OldLast")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.last = "NewLast"
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(last="NewLast")
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.last == "NewLast"
    assert db.execute.call_count == 1 # Only initial get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_only_phone(async_db_session):
    """Test UserService.update_user when only phone is changed."""
    db = async_db_session
    existing_user = user_model_stub(id=1, phone="123-456-7890")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.phone = "987-654-3210"
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(phone="987-654-3210")
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.phone == "987-654-3210"
    assert db.execute.call_count == 1 # Only initial get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_only_is_active(async_db_session):
    """Test UserService.update_user when only is_active status is changed."""
    db = async_db_session
    existing_user = user_model_stub(id=1, is_active=True)
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.is_active = False
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(is_active=False)
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.is_active is False
    assert db.execute.call_count == 1 # Only initial get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_only_is_superuser(async_db_session):
    """Test UserService.update_user when only is_superuser status is changed."""
    db = async_db_session
    existing_user = user_model_stub(id=1, is_superuser=False)
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.is_superuser = True
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(is_superuser=True)
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.is_superuser is True
    assert db.execute.call_count == 1 # Only initial get_user
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_set_first_name_to_none(async_db_session):
    """Test UserService.update_user when first_name is explicitly set to None."""
    db = async_db_session
    existing_user = user_model_stub(id=1, first="OldFirst")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.first = None
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(first=None)
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.first is None
    assert db.execute.call_count == 1 
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_set_last_name_to_none(async_db_session):
    """Test UserService.update_user when last_name is explicitly set to None."""
    db = async_db_session
    existing_user = user_model_stub(id=1, last="OldLast")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.last = None
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(last=None)
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.last is None
    assert db.execute.call_count == 1 
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_set_phone_to_none(async_db_session):
    """Test UserService.update_user when phone is explicitly set to None."""
    db = async_db_session
    existing_user = user_model_stub(id=1, phone="123-456-7890")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    def update_refresh_side_effect(user_obj):
        user_obj.phone = None
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(phone=None)
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.phone is None
    assert db.execute.call_count == 1 
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_password_not_updated_if_not_provided(async_db_session, monkeypatch):
    """Test UserService.update_user does not hash/update password if not provided in UserUpdate."""
    db = async_db_session
    existing_user = user_model_stub(id=1, password="existing_hashed_password")
    db.execute.return_value = mock_execute_result_factory(scalar_one_or_none_value=existing_user)

    mock_hash_password = AsyncMock(return_value="should_not_be_called")
    monkeypatch.setattr("app.api.v1.services.user.hash_password", mock_hash_password)

    def update_refresh_side_effect(user_obj):
        # Only update timestamp, password should remain as original
        user_obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        user_obj.role = DummyRole(id=user_obj.role_id)
    db.refresh.side_effect = update_refresh_side_effect

    user_in = UserUpdate(first="UpdatedFirst") # No password provided
    user = await UserService.update_user(db, 1, user_in)
    
    assert user is not None
    assert user.password == "existing_hashed_password" # Password should remain unchanged
    mock_hash_password.assert_not_awaited() # hash_password should NOT be called
    assert db.execute.call_count == 1
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

# --- New tests for app/api/v1/models/user.py (User model methods) ---

@pytest.mark.asyncio
async def test_user_model_set_password_hashes_correctly():
    """Test that User.set_password hashes the provided plain password."""
    user = UserModel(username="test", email="test@example.com", password="initial", role_id=2)
    plain_password = "MySecurePassword123"
    
    # Correctly patch the 'ph' instance itself, then its 'hash' method
    with patch("app.api.v1.models.user.ph") as mock_ph:
        mock_ph.hash.return_value = "mock_hashed_password_for_set"
        user.set_password(plain_password)

        mock_ph.hash.assert_called_once_with(plain_password)
        assert user.password == "mock_hashed_password_for_set"
        assert user.password != plain_password

@pytest.mark.asyncio
async def test_user_model_verify_password_success():
    """Test that User.verify_password returns True for a correct password."""
    user = UserModel(username="test", email="test@example.com", password="initial", role_id=2)
    plain_password = "CorrectPassword456"
    hashed_password_stored = "mock_hashed_password_for_verify_success"

    # Set the user's password to a pre-hashed value for testing verification
    user.password = hashed_password_stored

    # Correctly patch the 'ph' instance itself, then its 'verify' method
    with patch("app.api.v1.models.user.ph") as mock_ph:
        mock_ph.verify.return_value = True # Successfully verifies
        result = user.verify_password(plain_password)

        mock_ph.verify.assert_called_once_with(hashed_password_stored, plain_password)
        assert result is True

@pytest.mark.asyncio
async def test_user_model_verify_password_failure():
    """Test that User.verify_password returns False for an incorrect password."""
    user = UserModel(username="test", email="test@example.com", password="initial", role_id=2)
    wrong_password = "WrongPassword123"
    hashed_password_stored = "mock_hashed_password_for_verify_failure"

    # Set the user's password to a pre-hashed value for testing verification
    user.password = hashed_password_stored

    # Correctly patch the 'ph' instance itself, then its 'verify' method to simulate failure
    from argon2.exceptions import VerifyMismatchError # Import here to ensure it's the correct one
    with patch("app.api.v1.models.user.ph") as mock_ph:
        mock_ph.verify.side_effect = VerifyMismatchError("Simulated password mismatch")
        result = user.verify_password(wrong_password)

        mock_ph.verify.assert_called_once_with(hashed_password_stored, wrong_password)
        assert result is False

@pytest.mark.asyncio
async def test_read_user_404(async_client, monkeypatch):
    monkeypatch.setattr(UserService, "get_user", AsyncMock(return_value=None))
    response = await async_client.get("/api/v1/users/123")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_update_user_404(async_client, monkeypatch):
    monkeypatch.setattr(UserService, "update_user", AsyncMock(return_value=None))
    # Minimal valid user update body
    update_body = {"username": "updated_user"}
    response = await async_client.put("/api/v1/users/123", json=update_body)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_delete_user_404(async_client, monkeypatch):
    monkeypatch.setattr(UserService, "delete_user", AsyncMock(return_value=False))
    response = await async_client.delete("/api/v1/users/123")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_create_user_happy_path(async_client, monkeypatch):
    dummy = DummyUser(id=2, username="created_user", email="c@example.com")
    monkeypatch.setattr(UserService, "create_user", AsyncMock(return_value=dummy))
    post_body = {
        "username": "created_user",
        "email": "c@example.com",
        "password": "SuperSecret1!",
        "role_id": 1,
        "first": "First",
        "last": "Last"
    }
    response = await async_client.post("/api/v1/users/", json=post_body)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "created_user"
    assert data["email"] == "c@example.com"
    assert data["id"] == 2

@pytest.mark.asyncio
async def test_read_user_happy_path(async_client, monkeypatch):
    dummy_user = DummyUser(id=42, username="happy_user", email="happy@example.com")
    monkeypatch.setattr(UserService, "get_user", AsyncMock(return_value=dummy_user))
    response = await async_client.get("/api/v1/users/42")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 42
    assert data["username"] == "happy_user"
    assert data["email"] == "happy@example.com"

@pytest.mark.asyncio
async def test_update_user_happy_path(async_client, monkeypatch):
    dummy_user = DummyUser(id=43, username="updated_user", email="updated@example.com")
    monkeypatch.setattr(UserService, "update_user", AsyncMock(return_value=dummy_user))
    update_body = {"username": "updated_user"}
    response = await async_client.put("/api/v1/users/43", json=update_body)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 43
    assert data["username"] == "updated_user"

@pytest.mark.asyncio
async def test_delete_user_happy_path(async_client, monkeypatch):
    monkeypatch.setattr(UserService, "delete_user", AsyncMock(return_value=True))
    response = await async_client.delete("/api/v1/users/44")
    assert response.status_code == 204
    assert response.content == b""

@pytest.mark.asyncio
async def test_read_users(async_client):
    response = await async_client.get("/api/v1/users/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert data[0]["username"] == "admin_user"
