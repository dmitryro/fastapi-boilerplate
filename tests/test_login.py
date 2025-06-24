import pytest
import logging
from fastapi import status, HTTPException, Depends
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from app.main import app
# Import the main get_current_user dependency used in routes
from app.api.v1.dependencies import get_current_user as main_get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
from app.api.v1.models.user import User as UserModel
from app.api.v1.models.login import Login as LoginModel
from app.api.v1.schemas.login import LoginResponse, LoginRequest, Token
from app.api.v1.services.login import LoginService
from app.api.v1.services.auth import AuthService # Keep AuthService for its methods
# Import hash_password from the dedicated passwords module for creating dummy hashed passwords
from app.api.v1.security.passwords import hash_password 
from app.api.v1.security.jwt import create_access_token # Import actual function for mocking
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from typing import List


# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy classes for mocking dependencies
class DummyUser:
    id = 1
    username = "admin_user"
    # The password here needs to be pre-hashed using the correct method if used directly
    # For authenticate_user mock, this password will be passed to verify_password
    password = hash_password("testpass") 
    role_id = 1
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    updated_at = datetime.now(timezone.utc).replace(tzinfo=None)


class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]


# Async dummy current user (reused for authentication bypass)
async def dummy_get_current_user():
    logger.debug("Dummy get_current_user called for login tests")
    return DummyUser()

# Async dummy permission checker (reused for permission bypass)
def dummy_require_permission(permission: str):
    logger.debug(f"Dummy require permission called for login tests: {permission}")
    async def inner(user: DummyUser = Depends(dummy_get_current_user), db: AsyncSession = Depends(get_db)):
        logger.debug(f"Dummy permission check for: {permission} - returning user {user.username}")
        # In a real scenario, you'd check user roles/permissions here.
        # For testing, we assume the dummy user has the required permission.
        return user
    return inner

# Fixture to set up the async client with mocked dependencies for general routes
@pytest.fixture
async def async_client():
    # Override the main get_current_user dependency directly to bypass all authentication logic
    app.dependency_overrides[main_get_current_user] = dummy_get_current_user
    app.dependency_overrides[require_permission] = dummy_require_permission
    
    # Create an AsyncMock for DB session
    db = AsyncMock(spec=AsyncSession) # Use spec=AsyncSession for better type checking
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock() # Changed to MagicMock as it's not awaited in service code
    
    # Mock db.execute to return a MagicMock with proper scalars support
    mock_result_instance = MagicMock()
    mock_scalars_result_instance = MagicMock()
    mock_scalars_result_instance.first.return_value = DummyRole() # Default for role lookups if needed
    mock_scalars_result_instance.all.return_value = [] # Default for all()
    mock_result_instance.scalars.return_value = mock_scalars_result_instance
    mock_result_instance.scalar_one_or_none.return_value = DummyRole() # Default for scalar_one_or_none()
    db.execute.return_value = mock_result_instance 

    async def mock_get_db():
        logger.debug("Mock get_db called for general client tests")
        yield db

    app.dependency_overrides[get_db] = mock_get_db

    # Setup HTTPX client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Clear overrides after the test
    app.dependency_overrides.clear()

# Fixture for specific auth routes which might need different db mock setups
@pytest.fixture
async def mock_db():
    db = AsyncMock(spec=AsyncSession)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock() # Changed to MagicMock for consistency
    
    # Generic mock for db.execute to avoid NoneType errors initially
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None # Default no user/login found
    mock_result.scalars.return_value.all.return_value = [] # Default no results
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result
    return db

@pytest.fixture
async def async_client_for_auth_routes(mock_db):
    async def override_get_db():
        logger.debug("Mock get_db called for auth routes client tests")
        yield mock_db
    
    app.dependency_overrides[get_db] = override_get_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()


# Login model factory
def login_model_stub(**kwargs):
    # Ensure timezone-naive datetime objects for consistency with DB models
    return LoginModel(
        id=kwargs.get("id", 1),
        username=kwargs.get("username", "testuser"),
        password=kwargs.get("password", "some_hashed_password"),
        login_time=kwargs.get("login_time", datetime.now(timezone.utc).replace(tzinfo=None))
    )

# --- Service-level tests for app/api/v1/services/login.py ---

@pytest.mark.asyncio
# Patch AuthService.verify_password directly, as LoginService calls it
@patch("app.api.v1.services.auth.AuthService.verify_password", new_callable=AsyncMock) 
# Patch create_access_token where LoginService uses it
@patch("app.api.v1.services.login.create_access_token", new_callable=Mock) # Changed to Mock as it's not awaited
async def test_service_authenticate_user_success(mock_create_access_token, mock_auth_service_verify_password):
    """Test LoginService.authenticate_user with successful authentication."""
    db = AsyncMock()
    
    # This password should be pre-hashed as it would be stored in the DB
    hashed_db_password = hash_password("plain_password")
    mock_user_result = MagicMock()
    mock_user_result.scalar_one_or_none.return_value = UserModel(id=1, username="testuser", password=hashed_db_password, role_id=1)
    db.execute.return_value = mock_user_result

    # Simulate successful password verification by AuthService.verify_password
    mock_auth_service_verify_password.return_value = True

    # Simulate create_access_token returning the expected mock token
    mock_create_access_token.return_value = "mock_access_token"

    token = await LoginService.authenticate_user("testuser", "plain_password", db)
    assert token.access_token == "mock_access_token"
    assert token.token_type == "bearer"
    db.execute.assert_awaited_once()
    # Verify that AuthService.verify_password was called with correct arguments
    mock_auth_service_verify_password.assert_awaited_once_with("plain_password", hashed_db_password) # Arg order is (plain, hashed)
    mock_create_access_token.assert_called_once() # Now can assert this


@pytest.mark.asyncio
@patch("app.api.v1.services.auth.AuthService.verify_password", new_callable=AsyncMock)
async def test_service_authenticate_user_invalid_password(mock_auth_service_verify_password):
    """Test LoginService.authenticate_user with incorrect password."""
    db = AsyncMock()
    
    hashed_db_password = hash_password("correct_password")
    mock_user_result = MagicMock()
    mock_user_result.scalar_one_or_none.return_value = UserModel(id=1, username="testuser", password=hashed_db_password, role_id=1)
    db.execute.return_value = mock_user_result

    mock_auth_service_verify_password.return_value = False

    token = await LoginService.authenticate_user("testuser", "wrong_password", db)
    assert token is None
    db.execute.assert_awaited_once()
    mock_auth_service_verify_password.assert_awaited_once_with("wrong_password", hashed_db_password)


@pytest.mark.asyncio
async def test_service_authenticate_user_user_not_found():
    """Test LoginService.authenticate_user when user is not found."""
    db = AsyncMock()
    
    mock_user_result = MagicMock()
    mock_user_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_user_result

    token = await LoginService.authenticate_user("nonexistent_user", "password", db)
    assert token is None
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_all_logins():
    """Test LoginService.get_all_logins."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    expected_logins = [
        login_model_stub(id=1, username="login1"),
        login_model_stub(id=2, username="login2"),
    ]
    # Ensure all() returns a list, not just the first element
    mock_scalar_result.all.return_value = expected_logins
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    logins = await LoginService.get_all_logins(db)
    assert len(logins) == 2
    assert logins[0].username == "login1"
    assert logins[1].username == "login2"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_all_logins_empty():
    """Test LoginService.get_all_logins when no logins exist."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.all.return_value = []
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    logins = await LoginService.get_all_logins(db)
    assert len(logins) == 0
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_login():
    """Test LoginService.get_login."""
    db = AsyncMock()
    mock_result = MagicMock()
    expected_login = login_model_stub(id=1, username="testlogin")
    mock_result.scalar_one_or_none.return_value = expected_login
    db.execute.return_value = mock_result

    login = await LoginService.get_login(1, db)
    assert login.id == 1
    assert login.username == "testlogin"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_login_not_found():
    """Test LoginService.get_login when login is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    login = await LoginService.get_login(999, db)
    assert login is None
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_login(mock_db):
    """Test LoginService.create_login."""
    login_in = LoginRequest(username="newlogin", password="SecurePass123!")
    
    def refresh_side_effect(obj):
        obj.id = 1
        obj.login_time = datetime.now(timezone.utc).replace(tzinfo=None)
    mock_db.refresh.side_effect = refresh_side_effect

    login = await LoginService.create_login(login_in, mock_db)
    assert login.username == "newlogin"
    mock_db.add.assert_called_once() # Changed to assert_called_once
    mock_db.commit.assert_awaited_once()
    mock_db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_login_db_commit_failure(mock_db):
    """Test UserService.create_user with db.commit raising SQLAlchemyError."""
    login_in = LoginRequest(username="failcommit", password="Password1!")
    mock_db.commit.side_effect = SQLAlchemyError("Simulated commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated commit error"):
        await LoginService.create_login(login_in, mock_db)
    
    mock_db.add.assert_called_once() # Changed to assert_called_once
    mock_db.commit.assert_awaited_once()
    mock_db.refresh.assert_not_awaited() # Refresh should not be called if commit fails

@pytest.mark.asyncio
async def test_service_create_login_db_refresh_failure(mock_db):
    """Test UserService.create_user with db.refresh raising SQLAlchemyError."""
    login_in = LoginRequest(username="failrefresh", password="Password1!")
    mock_db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await LoginService.create_login(login_in, mock_db)
    
    mock_db.add.assert_called_once() # Changed to assert_called_once
    mock_db.commit.assert_awaited_once() # Commit should have been called before refresh
    mock_db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_login():
    """Test LoginService.update_login."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1, username="old_login")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    login_in = LoginRequest(username="updated_login", password="NewPassword1!")
    
    def refresh_side_effect(obj):
        obj.username = "updated_login"
        # Password would be hashed in the actual service, but here we just assign it for testing update logic
        obj.password = hash_password(login_in.password) # Ensure the password is "updated" with a hash
    db.refresh.side_effect = refresh_side_effect

    updated_login = await LoginService.update_login(1, login_in, db)

    assert updated_login.username == "updated_login"
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_login_not_found():
    """Test LoginService.update_login when login is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    login_in = LoginRequest(username="nonexistent", password="Password1!")
    updated_login = await LoginService.update_login(999, login_in, db)
    assert updated_login is None
    db.execute.assert_awaited_once()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_login_db_commit_failure():
    """Test LoginService.update_login with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1, username="old_login")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    login_in = LoginRequest(username="fail_commit", password="Password1!")
    db.commit.side_effect = SQLAlchemyError("Simulated update commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated update commit error"):
        await LoginService.update_login(1, login_in, db)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_login_db_refresh_failure():
    """Test LoginService.update_login with db.refresh raising SQLAlchemyError."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1, username="old_login")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    login_in = LoginRequest(username="fail_refresh", password="Password1!")
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await LoginService.update_login(1, login_in, db)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_login():
    """Test LoginService.delete_login."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    deleted = await LoginService.delete_login(1, db)
    assert deleted is True
    db.delete.assert_called_once_with(existing_login) 
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_login_db_delete_failure():
    """Test LoginService.delete_login with db.delete raising SQLAlchemyError."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    db.delete.side_effect = SQLAlchemyError("Simulated delete error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete error"):
        await LoginService.delete_login(1, db)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_login_db_commit_failure():
    """Test LoginService.delete_login with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_login = login_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_login
    db.execute.return_value = mock_result

    db.commit.side_effect = SQLAlchemyError("Simulated delete commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete commit error"):
        await LoginService.delete_login(1, db)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_login_not_found():
    """Test LoginService.delete_login when login is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    deleted = await LoginService.delete_login(999, db)
    assert deleted is False
    db.delete.assert_not_called()
    db.commit.assert_not_awaited()


# --- Route-level tests for app/api/v1/routes/login.py ---

@pytest.mark.asyncio
@patch("app.api.v1.services.auth.AuthService.verify_password", new_callable=AsyncMock)
# Removed patch for create_login_record as it does not exist and is not called by authenticate_user
async def test_route_post_login_success(mock_auth_service_verify_password, async_client_for_auth_routes, mock_db):
    """Test the POST /login route with successful authentication."""
    test_password_plain = "securepassword"
    # Use hash_password from app.api.v1.security.passwords to create the stored hash
    hashed_password_for_user = hash_password(test_password_plain) 
    dummy_user = UserModel(
        username="testuser", 
        password=hashed_password_for_user, # This password is now hashed correctly
        id=1, 
        role_id=1, 
        created_at=datetime.now(timezone.utc).replace(tzinfo=None), 
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    
    # Mock for user lookup using scalar_one_or_none() as expected by LoginService
    mock_user_query_result = MagicMock()
    mock_user_query_result.scalar_one_or_none.return_value = dummy_user
    mock_db.execute.return_value = mock_user_query_result
    
    mock_auth_service_verify_password.return_value = True # Simulate correct password verification

    # No need to mock create_login_record here, as authenticate_user doesn't call it.
    # The actual create_access_token (which is patched) is what gets called.

    payload = {"username": "testuser", "password": test_password_plain}
    logger.debug("Sending POST request to /api/v1/logins/")
    response = await async_client_for_auth_routes.post(
        "/api/v1/logins/",
        json=payload
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    # Assert that AuthService.verify_password was called with correct arguments
    mock_auth_service_verify_password.assert_awaited_once_with(test_password_plain, hashed_password_for_user)
    mock_db.execute.assert_awaited_once() # Only one execute for user lookup
    # Removed assertions for db.add, db.commit, db.refresh as they are not part of authenticate_user logic
    # The `LoginService.create_login` tests cover these interactions for creating new login records.


@pytest.mark.asyncio
@patch("app.api.v1.services.auth.AuthService.verify_password", new_callable=AsyncMock)
async def test_route_post_login_failure(mock_auth_service_verify_password, async_client_for_auth_routes, mock_db):
    """Test the POST /login route with failed authentication."""
    test_password_plain = "wrongpassword"
    # Use hash_password for the correct password that would be stored
    hashed_password_for_user = hash_password("correctpassword") 
    dummy_user = UserModel(
        username="wronguser", 
        password=hashed_password_for_user, # This password is now hashed correctly
        id=1, 
        role_id=1, 
        created_at=datetime.now(timezone.utc).replace(tzinfo=None), 
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )

    # Mock for user lookup using scalar_one_or_none() as expected by LoginService
    mock_user_query_result = MagicMock()
    mock_user_query_result.scalar_one_or_none.return_value = dummy_user
    mock_db.execute.return_value = mock_user_query_result
    
    mock_auth_service_verify_password.return_value = False # Simulate incorrect password

    payload = {"username": "wronguser", "password": test_password_plain}
    logger.debug("Sending POST request to /api/v1/logins/")
    response = await async_client_for_auth_routes.post(
        "/api/v1/logins/",
        json=payload
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Incorrect username or password"
    # Assert that AuthService.verify_password was called with correct arguments
    mock_auth_service_verify_password.assert_awaited_once_with(test_password_plain, hashed_password_for_user)
    mock_db.execute.assert_awaited_once() # Only one execute for user lookup
    mock_db.add.assert_not_called() # Changed to assert_not_called
    mock_db.commit.assert_not_awaited()
    mock_db.refresh.assert_not_awaited() # No refresh on failure


@pytest.mark.asyncio
async def test_route_read_logins(async_client, monkeypatch):
    """Test the GET /logins/ route with required permissions."""
    async def mock_get_all_logins(db):
        return [LoginResponse.from_orm(login_model_stub(id=1, username="login1"))]
    monkeypatch.setattr(LoginService, "get_all_logins", mock_get_all_logins)

    logger.debug("Sending GET request to /api/v1/logins/")
    response = await async_client.get(
        "/api/v1/logins/",
        headers={"Authorization": "Bearer fake-token"} # Our fixture bypasses validation, token is just present
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["username"] == "login1"

@pytest.mark.asyncio
async def test_route_read_login(async_client, monkeypatch):
    """Test the GET /logins/{login_id} route with required permissions."""
    async def mock_get_login(login_id, db):
        return LoginResponse.from_orm(login_model_stub(id=login_id, username="single_login"))
    monkeypatch.setattr(LoginService, "get_login", mock_get_login)

    logger.debug("Sending GET request to /api/v1/logins/1")
    response = await async_client.get(
        "/api/v1/logins/1",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "single_login"

@pytest.mark.asyncio
async def test_route_read_login_not_found(async_client, monkeypatch):
    """Test the GET /logins/{login_id} route when login is not found."""
    async def mock_get_login(login_id, db):
        return None
    monkeypatch.setattr(LoginService, "get_login", mock_get_login)

    logger.debug("Sending GET request to /api/v1/logins/999 (nonexistent)")
    response = await async_client.get(
        "/api/v1/logins/999",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Login not found"

@pytest.mark.asyncio
async def test_route_create_login(async_client, monkeypatch):
    """Test the POST /logins/create route with required permissions."""
    async def mock_create_login(login_in, db):
        return LoginResponse.from_orm(login_model_stub(id=1, username=login_in.username))
    monkeypatch.setattr(LoginService, "create_login", mock_create_login)

    payload = {"username": "newroute_login", "password": "RoutePassword1!"}
    logger.debug("Sending POST request to /api/v1/logins/create")
    response = await async_client.post(
        "/api/v1/logins/create",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["username"] == "newroute_login"
    assert "id" in data

@pytest.mark.asyncio
async def test_route_update_login(async_client, monkeypatch):
    """Test the PUT /logins/{login_id} route with required permissions."""
    async def mock_update_login(login_id, login_in, db):
        return LoginResponse.from_orm(login_model_stub(id=login_id, username=login_in.username))
    monkeypatch.setattr(LoginService, "update_login", mock_update_login)

    payload = {"username": "updated_route_login", "password": "UpdatedPassword1!"}
    logger.debug("Sending PUT request to /api/v1/logins/1")
    response = await async_client.put(
        "/api/v1/logins/1",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "updated_route_login"

@pytest.mark.asyncio
async def test_route_update_login_not_found(async_client, monkeypatch):
    """Test the PUT /logins/{login_id} route when login is not found."""
    async def mock_update_login(login_id, login_in, db):
        return None
    monkeypatch.setattr(LoginService, "update_login", mock_update_login)

    payload = {"username": "nonexistent_update", "password": "Password1!"}
    logger.debug("Sending PUT request to /api/v1/logins/999 (nonexistent)")
    response = await async_client.put(
        "/api/v1/logins/999",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Login not found"

@pytest.mark.asyncio
async def test_route_delete_login(async_client, monkeypatch):
    """Test the DELETE /logins/{login_id} route with required permissions."""
    async def mock_delete_login(login_id, db):
        return True
    monkeypatch.setattr(LoginService, "delete_login", mock_delete_login)

    logger.debug("Sending DELETE request to /api/v1/logins/1")
    response = await async_client.delete(
        "/api/v1/logins/1",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.text}")
    assert response.status_code == status.HTTP_204_NO_CONTENT

@pytest.mark.asyncio
async def test_route_delete_login_not_found(async_client, monkeypatch):
    """Test the DELETE /logins/{login_id} route when login is not found."""
    async def mock_delete_login(login_id, db):
        return False
    monkeypatch.setattr(LoginService, "delete_login", mock_delete_login)

    logger.debug("Sending DELETE request to /api/v1/logins/999 (nonexistent)")
    response = await async_client.delete(
        "/api/v1/logins/999",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Login not found"
