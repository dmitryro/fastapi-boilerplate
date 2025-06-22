import pytest
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock, patch
from app.api.v1.dependencies import get_current_user as init_get_current_user
from app.api.v1.dependencies.auth import get_current_user as auth_get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.config import SECRET_KEY, ALGORITHM
from app.core.db.session import get_db
import logging
import time
from cryptography.hazmat.primitives.asymmetric import rsa

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy classes to mock User and Role models
class DummyUser:
    id = 1
    username = "admin_user"
    role_id = 1

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

class DummyUserLimited:
    id = 2
    username = "limited_user"
    role_id = 2

class DummyRoleLimited:
    id = 2
    name = "limited"
    permissions = ["read"]

@pytest.fixture
async def async_db_session():
    session = AsyncMock(spec=AsyncSession)
    yield session

@pytest.fixture
def create_token():
    def _create_token(username: str, secret=SECRET_KEY, algorithm: str = ALGORITHM, exp: int = None):
        key = secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)
        payload = {"sub": username}
        if exp is not None:
            payload["exp"] = exp
        if algorithm == "RS256":
            # Generate RSA private key for RS256 tokens (for testing)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key = private_key
        return jwt.encode(payload, key, algorithm=algorithm)
    return _create_token

@pytest.fixture
def app():
    app = FastAPI()
    
    @app.get("/test-oauth2")
    async def test_oauth2(user: DummyUser = Depends(init_get_current_user)):
        return {"username": user.username}
    
    @app.get("/test-permission-read")
    async def test_permission(user: DummyUser = Depends(require_permission("read"))):
        return {"username": user.username}
    
    return app

@pytest.fixture
async def async_client(app, async_db_session):
    async def override_get_db():
        yield async_db_session
    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()

def test_dependencies_init_get_current_user_function_exists():
    import app.api.v1.dependencies as deps
    assert callable(deps.get_current_user)

def test_dependencies_init_imports():
    import app.api.v1.dependencies as deps
    assert hasattr(deps, "get_current_user")
    assert not hasattr(deps, "require_permission")


# --- Tests for app/api/v1/dependencies/__init__.py ---

@pytest.mark.asyncio
async def test_get_current_user_secret_key_with_get_secret_value(monkeypatch, async_db_session):
    """
    Covers branch where SECRET_KEY has get_secret_value method.
    """
    class Secret:
        def get_secret_value(self):
            return "secret_value_mock"

    # Patch SECRET_KEY inside the dependency module where it is used
    monkeypatch.setattr("app.api.v1.dependencies.SECRET_KEY", Secret())
    
    # Create a token using the mocked secret
    token = jwt.encode({"sub": "admin_user"}, "secret_value_mock", algorithm=ALGORITHM)
    
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result
    
    from app.api.v1.dependencies import get_current_user
    user = await get_current_user(token=token, db=async_db_session)
    assert user.username == "admin_user"


@pytest.mark.asyncio
async def test_get_current_user_missing_sub_claim_raises(async_db_session):
    """
    Test that get_current_user raises HTTPException if 'sub' is missing from JWT payload.
    """
    def mock_decode(token, key, algorithms):
        return {}  # no 'sub'

    with patch("app.api.v1.dependencies.__init__.jwt.decode", mock_decode):
        with pytest.raises(HTTPException) as exc_info:
            await init_get_current_user(token="token", db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

@pytest.mark.asyncio
async def test_get_current_user_user_not_found_raises(async_db_session):
    """
    Test that get_current_user raises HTTPException if user not found in DB.
    """
    def mock_decode(token, key, algorithms):
        return {"sub": "nonexistent"}

    with patch("app.api.v1.dependencies.__init__.jwt.decode", mock_decode):
        mock_result = MagicMock()
        mock_scalar_result = MagicMock()
        mock_scalar_result.first.return_value = None
        mock_result.scalars.return_value = mock_scalar_result
        async_db_session.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await init_get_current_user(token="token", db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

@pytest.mark.asyncio
async def test_get_current_user_jwt_error_raises(async_db_session):
    """
    Test get_current_user raises HTTPException on JWTError.
    """
    with patch("app.api.v1.dependencies.__init__.jwt.decode", side_effect=JWTError):
        with pytest.raises(HTTPException) as exc_info:
            await init_get_current_user(token="token", db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail


# --- Tests for require_permission (permissions.py) ---

@pytest.mark.asyncio
async def test_require_permission_admin_short_circuit():
    """
    If user.role_id == 1 (admin), should immediately return user without DB query.
    """
    require_perm = require_permission("any_permission")
    user = DummyUser()  # role_id == 1 (admin)
    db = AsyncMock(spec=AsyncSession)
    result_user = await require_perm(user=user, db=db)
    assert result_user == user
    db.execute.assert_not_awaited()

@pytest.mark.asyncio
async def test_require_permission_has_permission():
    """
    User has the required permission, should return user.
    """
    require_perm = require_permission("read")
    user = DummyUserLimited()
    role = DummyRoleLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    result_user = await require_perm(user=user, db=db)
    assert result_user == user

@pytest.mark.asyncio
async def test_require_permission_missing_permission():
    """
    User role permissions do not include required permission, should raise 403.
    """
    require_perm = require_permission("delete")
    user = DummyUserLimited()
    role = DummyRoleLimited()
    role.permissions = ["read", "write"]
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: delete"

@pytest.mark.asyncio
async def test_require_permission_no_role_found():
    """
    If role is not found in DB, should raise 403.
    """
    require_perm = require_permission("read")
    user = DummyUserLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_role_permissions_none():
    """
    If role.permissions is None, should raise 403.
    """
    require_perm = require_permission("read")
    user = DummyUserLimited()
    class RoleNonePerms:
        id = 2
        name = "broken"
        permissions = None
    role = RoleNonePerms()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_role_permissions_not_iterable():
    """
    If role.permissions is not iterable (e.g., int), should raise 403.
    """
    require_perm = require_permission("read")
    user = DummyUserLimited()
    class RoleBadPerms:
        id = 2
        name = "badrole"
        permissions = 123  # non-iterable
    role = RoleBadPerms()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_require_permission_none_permission_argument():
    """
    If permission argument is None, require_permission should raise 403.
    """
    require_perm = require_permission(None)
    user = DummyUserLimited()
    role = DummyRoleLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException):
        await require_perm(user=user, db=db)

@pytest.mark.asyncio
async def test_require_permission_empty_permission_string():
    """
    If permission argument is empty string, should raise 403.
    """
    require_perm = require_permission("")
    user = DummyUserLimited()
    role = DummyRoleLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException):
        await require_perm(user=user, db=db)


# --- Integration tests for FastAPI routes with dependency overrides ---

@pytest.mark.asyncio
async def test_oauth2_get_current_user_valid_token(async_client, create_token, async_db_session):
    token = create_token("admin_user")
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    response = await async_client.get(
        "/test-oauth2",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}

@pytest.mark.asyncio
async def test_oauth2_get_current_user_invalid_token(async_client):
    response = await async_client.get(
        "/test-oauth2",
        headers={"Authorization": "Bearer invalid_token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials or token expired"

@pytest.mark.asyncio
async def test_require_permission_admin_integration(async_client, app):
    async def dummy_get_current_user():
        return DummyUser()
    app.dependency_overrides[init_get_current_user] = dummy_get_current_user

    response = await async_client.get(
        "/test-permission-read",
        headers={"Authorization": "Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "admin_user"}

@pytest.mark.asyncio
async def test_require_permission_has_permission_integration(async_client, app, async_db_session):
    async def dummy_get_current_user():
        return DummyUserLimited()
    app.dependency_overrides[init_get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = DummyRoleLimited()
    async_db_session.execute.return_value = mock_result

    response = await async_client.get(
        "/test-permission-read",
        headers={"Authorization": f"Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "limited_user"}

@pytest.mark.asyncio
async def test_require_permission_no_permission_integration(async_client, app, async_db_session):
    async def dummy_get_current_user():
        return DummyUserLimited()
    app.dependency_overrides[init_get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    # Role with permissions that do NOT include "read"
    mock_result.scalar_one_or_none.return_value = type('Role', (), {"id": 2, "name": "limited", "permissions": ["write"]})()
    async_db_session.execute.return_value = mock_result

    response = await async_client.get(
        "/test-permission-read",
        headers={"Authorization": "Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_no_role_integration(async_client, app, async_db_session):
    async def dummy_get_current_user():
        return DummyUserLimited()
    app.dependency_overrides[init_get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    async_db_session.execute.return_value = mock_result

    response = await async_client.get(
        "/test-permission-read",
        headers={"Authorization": "Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Missing required permission: read"


# --- New tests for app/api/v1/dependencies/auth.py get_current_user ---

@pytest.mark.asyncio
async def test_auth_get_current_user_success(monkeypatch, async_db_session):
    """
    Test success path of auth.get_current_user with valid token and user found.
    """
    # Patch SECRET_KEY directly as a string, not as an object with get_secret_value()
    monkeypatch.setattr("app.api.v1.dependencies.auth.SECRET_KEY", "mock_secret")

    token = jwt.encode({"sub": "admin_user"}, "mock_secret", algorithm=ALGORITHM)

    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = DummyUser()
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result

    user = await auth_get_current_user(
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
        db=async_db_session,
    )
    assert user.username == "admin_user"


@pytest.mark.asyncio
async def test_auth_get_current_user_invalid_scheme_raises(async_db_session):
    """
    Test auth.get_current_user raises 401 if scheme is not bearer.
    """
    creds = HTTPAuthorizationCredentials(scheme="Basic", credentials="token")
    with pytest.raises(HTTPException) as exc_info:
        await auth_get_current_user(credentials=creds, db=async_db_session)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or missing token" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_jwt_error_raises(monkeypatch, async_db_session):
    """
    Test auth.get_current_user raises 401 on JWTError.
    """
    monkeypatch.setattr("app.api.v1.dependencies.auth.SECRET_KEY", "mock_secret")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalidtoken")
    with patch("app.api.v1.dependencies.auth.jwt.decode", side_effect=JWTError):
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate token" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_missing_sub_raises(monkeypatch, async_db_session):
    """
    Test auth.get_current_user raises 401 if JWT payload missing 'sub'.
    """
    monkeypatch.setattr("app.api.v1.dependencies.auth.SECRET_KEY", "mock_secret")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="validtoken")
    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={}):
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token payload" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_user_not_found_raises(monkeypatch, async_db_session):
    """
    Test auth.get_current_user raises 404 if user not found in DB.
    """
    monkeypatch.setattr("app.api.v1.dependencies.auth.SECRET_KEY", "mock_secret")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="validtoken")
    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={"sub": "nonexistent_user"}):
        mock_result = MagicMock()
        mock_scalar_result = MagicMock()
        mock_scalar_result.first.return_value = None
        mock_result.scalars.return_value = mock_scalar_result
        async_db_session.execute.return_value = mock_result
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=async_db_session)
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "User not found"

