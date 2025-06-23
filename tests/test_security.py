import pytest
import jwt
from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from base64 import b64encode
from datetime import datetime, timedelta, timezone
import logging

from app.api.v1.security.jwt import decode_jwt, create_access_token, get_current_user, require_permission, oauth2_scheme, bearer_scheme
from app.api.v1.security.passwords import hash_password, verify_password
from app.api.v1.models.user import User as UserModel
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
    password = None

    def verify_password(self, plain_password):
        return verify_password(self.password, plain_password)

    def set_password(self, password):
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
    session = AsyncMock(spec=AsyncSession)
    yield session

@pytest.fixture
def app():
    app = FastAPI()
    
    @app.get("/test-jwt")
    async def test_jwt(user: UserModel = Depends(get_current_user)):
        return {"username": user.username}
    
    @app.get("/test-permission")
    async def test_permission(user: UserModel = Depends(require_permission("read"))):
        return {"username": user.username}
    
    return app

@pytest.fixture
async def async_client(app, async_db_session):
    async def override_get_db():
        yield async_db_session
    
    async def override_get_current_user():
        return DummyUser()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()

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
async def test_get_current_user_bearer_invalid_scheme(async_db_session):
    """Test get_current_user with invalid Bearer scheme."""
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

    require_perm = require_permission("")
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user, async_db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Permission denied"

# Integration tests
@pytest.mark.asyncio
async def test_jwt_oauth2_integration(async_client, async_db_session):
    """Test JWT authentication via OAuth2 token."""
    token = jwt.encode({"sub": "admin_user"}, str(SECRET_KEY), algorithm=ALGORITHM)
    response = await async_client.get(
        "/test-jwt",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}

@pytest.mark.asyncio
async def test_jwt_basic_auth_integration(async_client, async_db_session):
    """Test Basic Auth integration."""
    user = DummyUser()
    user.set_password("SecurePass123!")
    auth_header = f"Basic {b64encode(b'admin_user:SecurePass123!').decode()}"
    response = await async_client.get(
        "/test-jwt",
        headers={"Authorization": auth_header}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}

@pytest.mark.asyncio
async def test_permission_integration(async_client, app, async_db_session):
    """Test permission check integration."""
    async def dummy_get_current_user():
        return DummyUser()
    app.dependency_overrides[get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    response = await async_client.get(
        "/test-permission",
        headers={"Authorization": "Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}
