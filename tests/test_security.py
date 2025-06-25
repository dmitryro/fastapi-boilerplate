import pytest
import jwt
from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials, OAuth2PasswordBearer, HTTPBearer
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

class DummyRoleWithSetPerms:
    # New dummy role for set permissions coverage
    id = 3
    name = "set_role"
    permissions = {"view", "edit"} # Using a set for permissions

class DummyRoleWithTuplePerms:
    # New dummy role for tuple permissions coverage
    id = 4
    name = "tuple_role"
    permissions = ("browse", "download") # Using a tuple for permissions

class DummyRoleEmptyTuplePerms:
    # Dummy role with empty tuple permissions for line 160 coverage
    id = 5
    name = "empty_tuple_role"
    permissions = ()

class DummyRoleEmptySetPerms:
    # Dummy role with empty set permissions for line 160 coverage
    id = 6
    name = "empty_set_role"
    permissions = set()

@pytest.fixture
async def async_db_session():
    # Provide a new AsyncMock session for each test to ensure isolation
    session = AsyncMock(spec=AsyncSession)
    yield session

@pytest.fixture
def app_with_security_routes():
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
    # decode_jwt now explicitly raises HTTPException(detail="Invalid token")
    with pytest.raises(HTTPException) as exc_info:
        decode_jwt("invalid_token")
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid token"

@pytest.mark.asyncio
async def test_create_access_token_default_expiry():
    """Test create_access_token with default expiry."""
    data = {"sub": "testuser"}
    token = create_access_token(data)
    # Fix: Add algorithms argument to jwt.decode
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
    # Fix: Add algorithms argument to jwt.decode
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
    # Passing token directly (simulating FastAPI's dependency resolution)
    user = await get_current_user(request, async_db_session, token=token, bearer=None)
    assert user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_oauth2_invalid_token(async_db_session):
    """Test get_current_user with invalid OAuth2 token."""
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        # Now expects "Invalid token" from `decode_jwt`, which get_current_user re-raises.
        await get_current_user(request, async_db_session, token="invalid_token", bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    # The get_current_user function's internal JWTError catch for token (oauth2_scheme)
    # still raises "Invalid token" as `decode_jwt` now raises it.
    assert exc_info.value.detail == "Invalid token" 

@pytest.mark.asyncio
async def test_get_current_user_oauth2_expired_token(async_db_session):
    """Test get_current_user with an expired OAuth2 token."""
    expired_payload = {"sub": "expired_user", "exp": (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()}
    expired_token = jwt.encode(expired_payload, str(SECRET_KEY), algorithm=ALGORITHM)

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        # Now expects "Token expired" from `decode_jwt`, which get_current_user re-raises.
        await get_current_user(request, async_db_session, token=expired_token, bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Token expired"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_get_current_user_oauth2_no_sub(async_db_session):
    """Test get_current_user with OAuth2 token missing sub claim."""
    token = jwt.encode({}, str(SECRET_KEY), algorithm=ALGORITHM)
    request = MagicMock(spec=Request)
    request.headers = {}
    # get_current_user explicitly raises ValueError for this case
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
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
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
        # Now expects "Invalid token" from `decode_jwt`, which get_current_user re-raises.
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid token"

@pytest.mark.asyncio
async def test_get_current_user_bearer_expired_token(async_db_session):
    """Test get_current_user with an expired HTTPBearer token."""
    expired_payload = {"sub": "expired_user", "exp": (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()}
    expired_token = jwt.encode(expired_payload, str(SECRET_KEY), algorithm=ALGORITHM)
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        # Now expects "Token expired" from `decode_jwt`, which get_current_user re-raises.
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Token expired"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}

@pytest.mark.asyncio
async def test_get_current_user_bearer_invalid_scheme(async_db_session):
    """Test get_current_user when HTTPBearer provides credentials with a non-Bearer scheme.
    This should cause get_current_user to fall through to basic auth/no auth path."""
    # When bearer.scheme is "Basic", the `if bearer.scheme.lower() == "bearer"` check in get_current_user fails.
    # Therefore, it will fall through to the Basic Auth attempt. Since no Basic Auth header is set on the request
    # in this test, it should hit the final "Not authenticated" exception.
    bearer_with_basic_scheme = HTTPAuthorizationCredentials(scheme="Basic", credentials="some_credentials_that_wont_be_decoded")
    request = MagicMock(spec=Request)
    request.headers = {} # No basic auth header either, to ensure it hits the final "Not authenticated"
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=bearer_with_basic_scheme)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Not authenticated" # This matches the final fallback in get_current_user
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer, Basic"}

@pytest.mark.asyncio
async def test_get_current_user_bearer_user_not_found(async_db_session):
    """Test get_current_user with HTTPBearer token for non-existent user."""
    # This test specifically targets line 111 in jwt.py
    token = jwt.encode({"sub": "nonexistent_bearer_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None # Simulate user not found
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=bearer)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "User not found"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_bearer_no_sub(async_db_session):
    """Test get_current_user with HTTPBearer token missing sub claim."""
    # This test targets line 106 in jwt.py (ValueError catch in bearer path)
    token = jwt.encode({}, str(SECRET_KEY), algorithm=ALGORITHM) # Empty payload to omit 'sub'
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    request = MagicMock(spec=Request)
    request.headers = {}
    with pytest.raises(ValueError, match="No sub claim in token"):
        await get_current_user(request, async_db_session, token=None, bearer=bearer)


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
    # Fix: Directly mock the .get() method of headers to return the auth_header
    request.headers.get.return_value = auth_header 
    user = await get_current_user(request, async_db_session, token=None, bearer=None)
    assert user.username == "admin_user"
    async_db_session.execute.assert_awaited()

@pytest.mark.asyncio
async def test_get_current_user_basic_auth_invalid_encoding(async_db_session):
    """Test get_current_user with invalid Basic Auth encoding."""
    request = MagicMock(spec=Request)
    # Fix: Directly mock the .get() method of headers to return invalid encoding
    request.headers.get.return_value = "Basic invalid_encoding"
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
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
    # Fix: Directly mock the .get() method of headers
    request.headers.get.return_value = auth_header
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid username or password" # This assertion should now pass

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
    # Fix: Directly mock the .get() method of headers
    request.headers.get.return_value = auth_header
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Invalid username or password" # This assertion should now pass

@pytest.mark.asyncio
async def test_get_current_user_no_auth(async_db_session):
    """Test get_current_user with no authentication provided."""
    request = MagicMock(spec=Request)
    # Ensure headers.get("Authorization") returns None by default for this test
    request.headers.get.return_value = None
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, async_db_session, token=None, bearer=None)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
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
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
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
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Role not found"

@pytest.mark.asyncio
async def test_require_permission_none_permissions(async_db_session):
    """Test require_permission when role permissions are None."""
    user = DummyUser()
    class RoleNonePerms:
        id = 1
        name = "broken"
        permissions = None # explicitly None
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleNonePerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_non_iterable_permissions(async_db_session):
    """Test require_permission when role permissions are non-iterable (e.g., int)."""
    user = DummyUser()
    class RoleBadPerms:
        id = 1
        name = "badrole"
        permissions = 123 # Non-iterable (not list/tuple/set)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleBadPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_empty_permissions(async_db_session):
    """Test require_permission when role permissions are empty."""
    user = DummyUser()
    class RoleEmptyPerms:
        id = 1
        name = "empty"
        permissions = [] # Empty list
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleEmptyPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_empty_string_permission(async_db_session):
    """Test require_permission with empty string permission argument."""
    user = DummyUser()
    # Mocking DummyRole here to ensure get_current_user path is clear
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("") # Passing an empty string here (targets line 160 as the `if not permission:` check)
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_type_error_in_perms(async_db_session):
    """Test require_permission when 'in' operator on permissions raises TypeError."""
    user = DummyUser()

    class BuggyPermissions:
        # This object will claim to be iterable (__iter__) but raise TypeError on __contains__
        def __iter__(self):
            yield 1 # Must yield at least one item to satisfy `isinstance(perms, (list, tuple, set))` check implicitly
        def __contains__(self, item):
            raise TypeError("Simulated TypeError from __contains__")

    class RoleBuggyPerms:
        id = 1
        name = "buggy"
        permissions = BuggyPermissions() # This object will cause TypeError on 'in' operator

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleBuggyPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_non_list_iterable_string(async_db_session):
    """Test require_permission when role permissions is a non-empty string (not list/tuple/set)."""
    # This test targets the `not isinstance(perms, (list, tuple, set))` part of line 160
    user = DummyUser()
    class RoleStringPerms:
        id = 1
        name = "string_role"
        permissions = "read_data" # A non-empty string, iterable, but not list/tuple/set

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleStringPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read") # Permission to check, doesn't matter much for this test
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_general_exception_in_perms(async_db_session):
    """Test require_permission when a general Exception occurs during permission check (line 162)."""
    user = DummyUser()

    class ExceptionRaisingPermissions:
        def __iter__(self):
            # This is needed so `isinstance(perms, (list, tuple, set))` is False
            # but it is still iterable for other checks.
            yield 1 
        def __contains__(self, item):
            # This will trigger the 'except Exception' block at line 162.
            raise Exception("Simulated general exception from __contains__")

    class RoleExceptionPerms:
        id = 1
        name = "exception_role"
        permissions = ExceptionRaisingPermissions()

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleExceptionPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_with_set_permissions(async_db_session):
    """Test require_permission when role permissions is a non-empty set."""
    # This test explicitly targets the `isinstance(perms, (list, tuple, set))`
    # for the `set` type, and `perms` being truthy, hitting the "pass" branch of line 160.
    user = DummyUser()
    user.role_id = DummyRoleWithSetPerms.id # Set user's role_id to match the new dummy role

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRoleWithSetPerms() # Return the set-based permissions role
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("view") # A permission that exists in DummyRoleWithSetPerms
    result_user = await require_perm(user, async_db_session)
    assert result_user.username == "admin_user" # The DummyUser is used, but its role_id is mocked
    
    # Fix: Use a more robust assertion for SQLAlchemy select objects.
    # Compile both the expected and actual statements to string for comparison.
    assert async_db_session.execute.await_count > 0 # Ensure execute was called at least once
    
    role_query_found = False
    for call_args in async_db_session.execute.call_args_list:
        statement = call_args.args[0]
        if isinstance(statement, Select) and any(table.name == 'roles' for table in statement.get_final_froms() if hasattr(table, 'name')):
            expected_statement = select(Role).filter(Role.id == DummyRoleWithSetPerms.id)
            # Compile both statements to text for robust comparison
            expected_sql_text = str(expected_statement.compile(compile_kwargs={"literal_binds": True}))
            actual_sql_text = str(statement.compile(compile_kwargs={"literal_binds": True}))
            
            # Normalize whitespace to make comparison more robust if minor formatting differences exist
            assert ' '.join(actual_sql_text.split()) == ' '.join(expected_sql_text.split())
            role_query_found = True
            break
    assert role_query_found, "Expected query for Role was not found in db.execute calls."

@pytest.mark.asyncio
async def test_require_permission_with_tuple_permissions(async_db_session):
    """Test require_permission when role permissions is a non-empty tuple."""
    # This test explicitly targets the `isinstance(perms, (list, tuple, set))`
    # for the `tuple` type, and `perms` being truthy, hitting the "pass" branch of line 160.
    user = DummyUser()
    user.role_id = DummyRoleWithTuplePerms.id # Set user's role_id to match the new dummy role

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRoleWithTuplePerms() # Return the tuple-based permissions role
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("browse") # A permission that exists in DummyRoleWithTuplePerms
    result_user = await require_perm(user, async_db_session)
    assert result_user.username == "admin_user" # The DummyUser is used, but its role_id is mocked
    
    assert async_db_session.execute.await_count > 0 # Ensure execute was called at least once
    
    role_query_found = False
    for call_args in async_db_session.execute.call_args_list:
        statement = call_args.args[0]
        if isinstance(statement, Select) and any(table.name == 'roles' for table in statement.get_final_froms() if hasattr(table, 'name')):
            expected_statement = select(Role).filter(Role.id == DummyRoleWithTuplePerms.id)
            expected_sql_text = str(expected_statement.compile(compile_kwargs={"literal_binds": True}))
            actual_sql_text = str(statement.compile(compile_kwargs={"literal_binds": True}))
            
            assert ' '.join(actual_sql_text.split()) == ' '.join(expected_sql_text.split())
            role_query_found = True
            break
    assert role_query_found, "Expected query for Role was not found in db.execute calls."

@pytest.mark.asyncio
async def test_require_permission_empty_tuple_permissions(async_db_session):
    """Test require_permission when role permissions is an empty tuple."""
    user = DummyUser()
    user.role_id = DummyRoleEmptyTuplePerms.id

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRoleEmptyTuplePerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("any_permission") # The permission doesn't matter, it should be denied
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

    # Verify the database call for the role
    assert async_db_session.execute.await_count > 0
    role_query_found = False
    for call_args in async_db_session.execute.call_args_list:
        statement = call_args.args[0]
        if isinstance(statement, Select) and any(table.name == 'roles' for table in statement.get_final_froms() if hasattr(table, 'name')):
            expected_statement = select(Role).filter(Role.id == DummyRoleEmptyTuplePerms.id)
            expected_sql_text = str(expected_statement.compile(compile_kwargs={"literal_binds": True}))
            actual_sql_text = str(statement.compile(compile_kwargs={"literal_binds": True}))
            assert ' '.join(actual_sql_text.split()) == ' '.join(expected_sql_text.split())
            role_query_found = True
            break
    assert role_query_found, "Expected query for Role (empty tuple) was not found in db.execute calls."

@pytest.mark.asyncio
async def test_require_permission_empty_set_permissions(async_db_session):
    """Test require_permission when role permissions is an empty set."""
    user = DummyUser()
    user.role_id = DummyRoleEmptySetPerms.id

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRoleEmptySetPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("another_permission") # The permission doesn't matter, it should be denied
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

    # Verify the database call for the role
    assert async_db_session.execute.await_count > 0
    role_query_found = False
    for call_args in async_db_session.execute.call_args_list:
        statement = call_args.args[0]
        if isinstance(statement, Select) and any(table.name == 'roles' for table in statement.get_final_froms() if hasattr(table, 'name')):
            expected_statement = select(Role).filter(Role.id == DummyRoleEmptySetPerms.id)
            expected_sql_text = str(expected_statement.compile(compile_kwargs={"literal_binds": True}))
            actual_sql_text = str(statement.compile(compile_kwargs={"literal_binds": True}))
            assert ' '.join(actual_sql_text.split()) == ' '.join(expected_sql_text.split())
            role_query_found = True
            break
    assert role_query_found, "Expected query for Role (empty set) was not found in db.execute calls."


# Integration tests
@pytest.mark.asyncio
async def test_jwt_oauth2_integration(async_client_for_security_tests, app_with_security_routes, async_db_session):
    """Test JWT authentication via OAuth2 token integration."""
    # Mock db.execute for get_current_user to return a user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    # Temporarily override HTTPBearer to return None to ensure OAuth2PasswordBearer is prioritized.
    # This directly uses app_with_security_routes for dependency overrides.
    async def mock_bearer_scheme_none():
        return None
    app_with_security_routes.dependency_overrides[bearer_scheme] = mock_bearer_scheme_none

    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    response = await async_client_for_security_tests.get(
        "/test-jwt",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    async_db_session.execute.assert_awaited()
    del app_with_security_routes.dependency_overrides[bearer_scheme]


@pytest.mark.asyncio
async def test_jwt_httpbearer_integration(async_client_for_security_tests, app_with_security_routes, async_db_session):
    """Test JWT authentication via HTTPBearer token integration."""
    user = DummyUser()
    user.set_password("SecurePass123!")

    # Mock db.execute for get_current_user to return the user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = user
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    # Temporarily override OAuth2PasswordBearer to return None
    # This ensures the `token` parameter in get_current_user is None, forcing `bearer` path.
    async def mock_oauth2_scheme_none():
        return None
    app_with_security_routes.dependency_overrides[oauth2_scheme] = mock_oauth2_scheme_none

    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    response = await async_client_for_security_tests.get(
        "/test-jwt",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    async_db_session.execute.assert_awaited()
    
    del app_with_security_routes.dependency_overrides[oauth2_scheme]


@pytest.mark.asyncio
async def test_jwt_basic_auth_integration(async_client_for_security_tests, app_with_security_routes, async_db_session):
    """Test Basic Auth integration."""
    user = DummyUser()
    user.set_password("SecurePass123!")
    
    # Mock db.execute for get_current_user to return the user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = user
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    # Temporarily override OAuth2PasswordBearer and HTTPBearer to return None
    # for this specific test, allowing the Basic Auth path to be hit without interference.
    async def mock_oauth2_scheme_none():
        return None
    async def mock_bearer_scheme_none():
        return None
    app_with_security_routes.dependency_overrides[oauth2_scheme] = mock_oauth2_scheme_none
    app_with_security_routes.dependency_overrides[bearer_scheme] = mock_bearer_scheme_none

    auth_header = f"Basic {b64encode(b'admin_user:SecurePass123!').decode()}"
    response = await async_client_for_security_tests.get(
        "/test-jwt",
        headers={"Authorization": auth_header}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
    async_db_session.execute.assert_awaited()
    
    del app_with_security_routes.dependency_overrides[oauth2_scheme]
    del app_with_security_routes.dependency_overrides[bearer_scheme]


@pytest.mark.asyncio
async def test_permission_integration(async_client_for_security_tests, async_db_session):
    """Test permission check integration."""
    # Mock db.execute to return user for get_current_user and role for require_permission
    async def mock_execute_side_effect(statement):
        # Check if the query is for User or Role model
        # Using statement.get_final_froms() for broader compatibility with SQLAlchemy queries
        if isinstance(statement, Select) and any(table.name == 'users' for table in statement.get_final_froms() if hasattr(table, 'name')):
            mock_user_result = MagicMock()
            mock_user_scalar_result = MagicMock()
            mock_user_scalar_result.first.return_value = DummyUser()
            mock_user_result.scalars.return_value = mock_user_scalar_result
            return mock_user_result
        elif isinstance(statement, Select) and any(table.name == 'roles' for table in statement.get_final_froms() if hasattr(table, 'name')):
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

@pytest.mark.asyncio
async def test_require_permission_not_list_tuple_set_but_truthy(async_db_session):
    """Covers perms that are truthy but not list/tuple/set (e.g., custom object)."""
    user = DummyUser()

    class PermsObj:
        def __bool__(self): return True  # Truthy
        # Not a list/tuple/set, not iterable

    class RoleCustomPerms:
        id = 1
        name = "custom"
        permissions = PermsObj()

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleCustomPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_truthy_non_collection(async_db_session):
    """Covers line 160 with permissions=1 (truthy, not list/tuple/set)."""
    user = DummyUser()
    class RoleIntPerms:
        id = 1
        name = "int_role"
        permissions = 1  # truthy, not list/tuple/set
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleIntPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result
    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"

@pytest.mark.asyncio
async def test_require_permission_truthy_noniterable_non_collection(async_db_session):
    """Covers line 160: perms is truthy, not list/tuple/set, and not iterable."""
    user = DummyUser()

    class TruthyNonIterable:
        def __bool__(self): return True

    class RoleCustomPerms:
        id = 1
        name = "custom"
        permissions = TruthyNonIterable()  # Not list/tuple/set, not iterable

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = RoleCustomPerms()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    require_perm = require_permission("read")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Permission denied"
