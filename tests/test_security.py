import pytest
import jwt
from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select # Function for building SELECT statements
from sqlalchemy.sql.selectable import Select # Type for checking SELECT statement instances
from base64 import b64encode
from datetime import datetime, timedelta, timezone
import logging

from app.api.v1.security.jwt import decode_jwt, create_access_token, get_current_user, require_permission, oauth2_scheme, bearer_scheme
from app.api.v1.security.passwords import hash_password, verify_password
from app.api.v1.models.user import User as UserModel
from app.api.v1.models.role import Role # Import Role model for side_effect mocking
from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from app.core.db.session import get_db

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy classes to mock User and Role models
class DummyUser:
    id = 1
    username = "admin_user"
    role_id = 1
    password = None # This will be set by set_password mock

    def verify_password(self, plain_password):
        # Use the real verify_password from the app's security module
        return verify_password(self.password, plain_password)

    def set_password(self, password):
        # Use the real hash_password from the app's security module
        self.password = hash_password(password)

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

class DummyUserLimited:
    id = 2
    username = "limited_user"
    role_id = 2
    password = None

    def verify_password(self, plain_password):
        return verify_password(self.password, plain_password)

    def set_password(self, password):
        self.password = hash_password(password)

class DummyRoleLimited:
    id = 2
    name = "limited"
    permissions = ["read"]

@pytest.fixture
async def async_db_session():
    # Provide a new AsyncMock session for each test to ensure isolation
    session = AsyncMock(spec=AsyncSession)
    yield session

@pytest.fixture
def app_with_security_routes():
    # Use a different fixture name to avoid confusion with `app` in conftest.py
    # This app is specifically for testing the routes with security dependencies
    app_instance = FastAPI()
    
    @app_instance.get("/test-jwt")
    async def test_jwt_route(user: UserModel = Depends(get_current_user)):
        return {"username": user.username}
    
    @app_instance.get("/test-permission")
    async def test_permission_route(user: UserModel = Depends(require_permission("read"))):
        return {"username": user.username}
    
    return app_instance

@pytest.fixture
async def async_client_for_security_tests(app_with_security_routes, async_db_session):
    async def override_get_db():
        yield async_db_session
    
    app_with_security_routes.dependency_overrides[get_db] = override_get_db
    
    # We are explicitly NOT overriding get_current_user here
    # because we want the integration tests to hit the *actual* get_current_user logic.

    async with AsyncClient(transport=ASGITransport(app=app_with_security_routes), base_url="http://test") as client:
        yield client
    app_with_security_routes.dependency_overrides.clear() # Clear overrides after the test

# Tests for app/api/v1/security/passwords.py
@pytest.mark.asyncio
async def test_hash_password():
    """Test hash_password creates a valid Argon2 hash."""
    password = "SecurePass123!"
    hashed = hash_password(password)
    assert hashed != password
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, password) is True

@pytest.mark.asyncio
async def test_verify_password_correct():
    """Test verify_password with correct password."""
    password = "SecurePass123!"
    hashed = hash_password(password)
    assert verify_password(hashed, password) is True

@pytest.mark.asyncio
async def test_verify_password_incorrect():
    """Test verify_password with incorrect password."""
    password = "SecurePass123!"
    hashed = hash_password(password)
    assert verify_password(hashed, "WrongPass123!") is False

# Tests for app/api/v1/security/jwt.py
@pytest.mark.asyncio
async def test_decode_jwt_valid():
    """Test decode_jwt with a valid token."""
    token = jwt.encode({"sub": "testuser"}, str(SECRET_KEY), algorithm=ALGORITHM)
    payload = decode_jwt(token)
    assert payload["sub"] == "testuser"

@pytest.mark.asyncio
async def test_decode_jwt_invalid():
    """Test decode_jwt with an invalid token."""
    with pytest.raises(HTTPException) as exc_info:
        decode_jwt("invalid_token")
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"

@pytest.mark.asyncio
async def test_create_access_token_default_expiry():
    """Test create_access_token with default expiry."""
    data = {"sub": "testuser"}
    token = create_access_token(data)
    payload = jwt.decode(token, str(SECRET_KEY), algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload
    exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    expected_exp = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    assert abs((exp_time - expected_exp).total_seconds()) < 60  # Allow small time delta

@pytest.mark.asyncio
async def test_create_access_token_custom_expiry():
    """Test create_access_token with custom expiry."""
    data = {"sub": "testuser"}
    expires_delta = timedelta(minutes=5)
    token = create_access_token(data, expires_delta)
    payload = jwt.decode(token, str(SECRET_KEY), algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    expected_exp = datetime.now(timezone.utc) + expires_delta
    assert abs((exp_time - expected_exp).total_seconds()) < 60

@pytest.mark.asyncio
async def test_get_current_user_oauth2_valid_token(async_db_session):
    """Test get_current_user with valid OAuth2 token."""
    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {}
    user = await get_current_user(request, async_db_session, token=token, bearer=None)
    assert user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_oauth2_invalid_token(async_db_session):
    """Test get_current_user with invalid OAuth2 token."""
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token="invalid_token", bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid Bearer token"

@pytest.mark.asyncio
async def test_get_current_user_oauth2_expired_token(async_db_session):
    """Test get_current_user with an expired OAuth2 token."""
    expired_payload = {"sub": "expired_user", "exp": (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()}
    expired_token = jwt.encode(expired_payload, str(SECRET_KEY), algorithm=ALGORITHM)

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=expired_token, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token expired"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_get_current_user_oauth2_no_sub(async_db_session):
    """Test get_current_user with OAuth2 token missing sub claim."""
    token = jwt.encode({}, str(SECRET_KEY), algorithm=ALGORITHM)
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(ValueError, match="No sub claim in token"):
        await get_current_user(request, async_db_session, token=token, bearer=None)

@pytest.mark.asyncio
async def test_get_current_user_oauth2_user_not_found(async_db_session):
    """Test get_current_user with OAuth2 token for non-existent user."""
    token = jwt.encode({"sub": "nonexistent"}, str(SECRET_KEY), algorithm=ALGORITHM)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=token, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "User not found"

@pytest.mark.asyncio
async def test_get_current_user_bearer_valid_token(async_db_session):
    """Test get_current_user with valid HTTPBearer token."""
    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {}
    user = await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_bearer_invalid_token(async_db_session):
    """Test get_current_user with invalid HTTPBearer token."""
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid_token")
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid Bearer token"

@pytest.mark.asyncio
async def test_get_current_user_bearer_expired_token(async_db_session):
    """Test get_current_user with an expired HTTPBearer token."""
    expired_payload = {"sub": "expired_user", "exp": (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()}
    expired_token = jwt.encode(expired_payload, str(SECRET_KEY), algorithm=ALGORITHM)
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token expired"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_get_current_user_bearer_invalid_scheme(async_db_session):
    """Test get_current_user with invalid Bearer scheme. This should fall to no-auth or basic auth."""
    bearer = HTTPAuthorizationCredentials(scheme="Basic", credentials="token")
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Not authenticated"


@pytest.mark.asyncio
async def test_get_current_user_basic_auth_valid(async_db_session):
    """Test get_current_user with valid Basic Auth."""
    user = DummyUser()
    user.set_password("SecurePass123!")
    username = "admin_user"
    password = "SecurePass123!"
    auth_header = f"Basic {b64encode(f'{username}:{password}'.encode()).decode()}"
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = user
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {"Authorization": auth_header}
    user = await get_current_user(request, async_db_session, token=None, bearer=None)
    assert user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_basic_auth_invalid_encoding(async_db_session):
    """Test get_current_user with invalid Basic Auth encoding."""
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Basic invalid_encoding"}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid Basic Auth encoding"

@pytest.mark.asyncio
async def test_get_current_user_basic_auth_invalid_credentials(async_db_session):
    """Test get_current_user with invalid Basic Auth credentials."""
    user = DummyUser()
    user.set_password("SecurePass123!")
    username = "admin_user"
    password = "WrongPass123!"
    auth_header = f"Basic {b64encode(f'{username}:{password}'.encode()).decode()}"
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = user
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {"Authorization": auth_header}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid username or password"

@pytest.mark.asyncio
async def test_get_current_user_basic_auth_no_user(async_db_session):
    """Test get_current_user with Basic Auth for non-existent user."""
    username = "nonexistent"
    password = "SecurePass123!"
    auth_header = f"Basic {b64encode(f'{username}:{password}'.encode()).decode()}"
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {"Authorization": auth_header}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid username or password"

@pytest.mark.asyncio
async def test_get_current_user_no_auth(async_db_session):
    """Test get_current_user with no authentication provided."""
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Not authenticated"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer, Basic"}

@pytest.mark.asyncio
async def test_require_permission_has_permission(async_db_session):
    """Test require_permission when user has the required permission."""
    user = DummyUser()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    result_user = await require_perm(user, async_db_session)
    assert result_user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_require_permission_no_permission(async_db_session):
    """Test require_permission when user lacks the required permission."""
    user = DummyUserLimited()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRoleLimited()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("delete")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_role_not_found(async_db_session):
    """Test require_permission when role is not found."""
    user = DummyUser()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Role not found"

@pytest.mark.asyncio
async def test_require_permission_none_permissions(async_db_session):
    """Test require_permission when role permissions are None."""
    user = DummyUser()
    class RoleNonePerms:
        id = 1
        name = "broken"
        permissions = None
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleNonePerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_non_iterable_permissions(async_db_session):
    """Test require_permission when role permissions are non-iterable."""
    user = DummyUser()
    class RoleBadPerms:
        id = 1
        name = "badrole"
        permissions = 123
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleBadPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_empty_permissions(async_db_session):
    """Test require_permission when role permissions are empty."""
    user = DummyUser()
    class RoleEmptyPerms:
        id = 1
        name = "empty"
        permissions = []
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleEmptyPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_empty_string_permission(async_db_session):
    """Test require_permission with empty string permission."""
    user = DummyUser()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("") # Passing an empty string here
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_type_error_in_perms(async_db_session): # NEW TEST for line 136
    """Test require_permission when 'in' operator on permissions raises TypeError."""
    user = DummyUser()

    class BuggyPermissions:
        # This object will claim to be iterable (has __iter__) but will raise TypeError
        # when __contains__ is called, simulating an unexpected type or corrupted iterable.
        def __iter__(self):
            yield 1 # Must yield at least one item to satisfy 'hasattr(perms, "__iter__")' check

        def __contains__(self, item):
            # Explicitly raise TypeError when 'in' operator is used.
            raise TypeError("Simulated TypeError from __contains__")

    class RoleBuggyPerms:
        id = 1
        name = "buggy"
        permissions = BuggyPermissions()

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleBuggyPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"


# Integration tests (MODIFIED to run actual get_current_user)
@pytest.mark.asyncio
async def test_jwt_oauth2_integration(async_client_for_security_tests, async_db_session):
    """Test JWT authentication via OAuth2 token."""
    # Mock db.execute for get_current_user to return a user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    response = await async_client_for_security_tests.get(
        "/test-jwt",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    async_db_session.execute.assert_awaited() # Ensure DB query was called

@pytest.mark.asyncio
async def test_jwt_basic_auth_integration(async_client_for_security_tests, app_with_security_routes, async_db_session):
    """Test Basic Auth integration."""
    user = DummyUser()
    user.set_password("SecurePass123!") # Set password for basic auth verification
    
    # Mock db.execute for get_current_user to return the user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = user
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    # Temporarily override OAuth2PasswordBearer and HTTPBearer to return None
    # for this specific test, allowing the Basic Auth path to be hit without interference.
    async def mock_oauth2_scheme():
        return None
    async def mock_bearer_scheme():
        return None
    app_with_security_routes.dependency_overrides[oauth2_scheme] = mock_oauth2_scheme
    app_with_security_routes.dependency_overrides[bearer_scheme] = mock_bearer_scheme

    auth_header = f"Basic {b64encode(b'admin_user:SecurePass123!').decode()}"
    response = await async_client_for_security_tests.get(
        "/test-jwt",
        headers={"Authorization": auth_header}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    async_db_session.execute.assert_awaited()
    
    # Clean up overrides after test
    del app_with_security_routes.dependency_overrides[oauth2_scheme]
    del app_with_security_routes.dependency_overrides[bearer_scheme]


@pytest.mark.asyncio
async def test_permission_integration(async_client_for_security_tests, async_db_session):
    """Test permission check integration."""
    # Mock db.execute to return user for get_current_user and role for require_permission
    async def mock_execute_side_effect(statement):
        # Check if the query is for User or Role model
        if isinstance(statement, Select) and any(table.name == 'users' for table in statement.froms if hasattr(table, 'name')):
            mock_user_result = MagicMock()
            mock_user_scalar_result = MagicMock()
            mock_user_scalar_result.first.return_value = DummyUser()
            mock_user_result.scalars.return_value = mock_user_scalar_result
            return mock_user_result
        elif isinstance(statement, Select) and any(table.name == 'roles' for table in statement.froms if hasattr(table, 'name')):
            mock_role_result = MagicMock()
            mock_role_scalar_result = MagicMock()
            mock_role_scalar_result.first.return_value = DummyRole()
            mock_role_result.scalars.return_value = mock_role_scalar_result
            return mock_role_result
        raise ValueError(f"Unexpected query: {statement}")

    async_db_session.execute.side_effect = mock_execute_side_effect

    # Provide a valid token so get_current_user succeeds
    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    response = await async_client_for_security_tests.get(
        "/test-permission",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    # Assert that db.execute was called multiple times (once for user, once for role)
    assert async_db_session.execute.call_count >= 2


