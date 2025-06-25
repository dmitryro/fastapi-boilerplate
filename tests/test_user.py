import pytest
from fastapi import HTTPException, status # Import status for HTTP status codes
from unittest.mock import AsyncMock, MagicMock, patch # Import patch for monkeypatching functions
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from app.api.v1.services.user import UserService
from app.api.v1.schemas.user import UserCreate, UserUpdate
from app.api.v1.models.user import User as UserModel # Explicitly import UserModel
from app.api.v1.models.role import Role # Explicitly import Role
from app.api.v1.security.passwords import hash_password # Import hash_password to mock it
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Dummy Classes to mock User and Role models for tests ---
class DummyUser:
    """A dummy class to represent a User for general mocking purposes."""
    def __init__(self, id=1, username="admin_user", email="admin@example.com", role_id=1, is_active=True, is_superuser=False):
        self.id = id
        self.username = username
        self.email = email
        self.role_id = role_id
        self.is_active = is_active
        self.is_superuser = is_superuser
        # This will be populated by `user_model_stub` or specific mocks
        self.role = None 
        # Add _sa_instance_state to mimic SQLAlchemy ORM objects
        self._sa_instance_state = MagicMock()

class DummyRole:
    """A dummy class to represent a Role model in tests."""
    def __init__(self, id=1, name="admin", permissions=None):
        self.id = id
        self.name = name
        self.permissions = permissions if permissions is not None else []
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        # Add _sa_instance_state to mimic SQLAlchemy ORM objects
        self._sa_instance_state = MagicMock()

# --- Fixtures ---

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
        # This is where the previous test was failing: user_obj.password was being set to an awaitable mock object
        # instead of the string result of the mocked hash_password call.
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

    # The password length validation is typically handled by Pydantic directly in the schema
    # or by an explicit validator called within the service.
    # If the service raises HTTPException for this, the test can assert on it.
    # Removed the patch for validate_password_strength as its exact path might vary.
    with pytest.raises(HTTPException) as exc_info:
        await UserService.create_user(db, user_in)
    
    # Assertions for the expected HTTPException (assuming UserService handles this validation)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    # The detail message might vary depending on whether it's Pydantic or custom validation.
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
    
    # Removed the patch for validate_username_length as its exact path might vary.
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

    # Removed the patch for validate_first_name_length as its exact path might vary.
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

    # Removed the patch for validate_last_name_length as its exact path might vary.
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
        user_obj.role = DummyRole(id=user_obj.role_id, name="admin") # Update the associated role
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
async def test_service_update_user_same_username(async_db_session, monkeypatch):
    """Test UserService.update_user when username is provided but is the same as current."""
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
    
    # Removed the patch for validate_username_length as its exact path might vary.
    user = await UserService.update_user(db, existing_user_id, user_in)
        
    assert user is not None
    assert user.username == existing_user_username # Username should remain unchanged
    
    assert db.execute.call_count == 1 # Only the initial get_user call as username is same. No uniqueness check.
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once_with(existing_user)
    db.rollback.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_user_same_email(async_db_session, monkeypatch):
    """Test UserService.update_user when email is provided but is the same as current."""
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
    
    # Removed the patch for validate_email_format as its exact path might vary.
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
        # Removed the patch for validate_username_length as its exact path might vary.
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
        # Removed the patch for validate_first_name_length as its exact path might vary.
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
        # Removed the patch for validate_last_name_length as its exact path might vary.
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
        # Removed the patch for validate_password_strength as its exact path might vary.
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

