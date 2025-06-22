import pytest
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from unittest.mock import AsyncMock, MagicMock, patch
from app.api.v1.dependencies import get_current_user as init_get_current_user
from app.api.v1.dependencies.auth import get_current_user as auth_get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.api.v1.security.jwt import get_current_user as jwt_get_current_user
from app.core.config import SECRET_KEY, ALGORITHM
from app.core.db.session import get_db
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
    def _create_token(username: str, secret=SECRET_KEY, algorithm: str = ALGORITHM):
        key = secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)
        payload = {"sub": username}
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
async def test_oauth2_get_current_user_no_sub(async_client, create_token, async_db_session):
    token = create_token("")
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result
    response = await async_client.get(
        "/test-oauth2",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials or token expired"

@pytest.mark.asyncio
async def test_oauth2_get_current_user_no_user(async_client, create_token, async_db_session):
    token = create_token("nonexistent_user")
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    async_db_session.execute.return_value = mock_result
    response = await async_client.get(
        "/test-oauth2",
        headers={"Authorization": f"Bearer {token}"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials or token expired"

@pytest.mark.asyncio
async def test_auth_get_current_user_credentials_scheme_not_bearer():
    creds = HTTPAuthorizationCredentials(scheme="Basic", credentials="token123")
    db = AsyncMock()
    with pytest.raises(HTTPException) as exc_info:
        await auth_get_current_user(credentials=creds, db=db)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or missing token" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_invalid_token_payload():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token123")
    db = AsyncMock()
    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={}):
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=db)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token payload" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_invalid_token_jwt_error():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token123")
    db = AsyncMock()
    with patch("app.api.v1.dependencies.auth.jwt.decode", side_effect=JWTError):
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=db)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate token" in exc_info.value.detail

@pytest.mark.asyncio
async def test_auth_get_current_user_user_not_found():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token123")
    db = AsyncMock()
    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={"sub": "nonexistent_user"}):
        mock_result = MagicMock()
        mock_scalar_result = MagicMock()
        mock_scalar_result.first.return_value = None
        mock_result.scalars.return_value = mock_scalar_result
        db.execute.return_value = mock_result
        with pytest.raises(HTTPException) as exc_info:
            await auth_get_current_user(credentials=creds, db=db)
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "User not found"

@pytest.mark.asyncio
async def test_auth_get_current_user_success():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token123")
    db = AsyncMock()
    dummy_user = DummyUser()
    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={"sub": dummy_user.username}):
        mock_result = MagicMock()
        mock_scalar_result = MagicMock()
        mock_scalar_result.first.return_value = dummy_user
        mock_result.scalars.return_value = mock_scalar_result
        db.execute.return_value = mock_result
        user = await auth_get_current_user(credentials=creds, db=db)
        assert user.username == dummy_user.username

@pytest.mark.asyncio
async def test_require_permission_admin():
    require_perm = require_permission("create")
    user_instance = DummyUser()
    db = AsyncMock(spec=AsyncSession)
    user = await require_perm(user=user_instance, db=db)
    assert user.username == "admin_user"

@pytest.mark.asyncio
async def test_require_permission_has_permission():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = DummyRoleLimited()
    db.execute.return_value = mock_result
    user = await require_perm(user=user_instance, db=db)
    assert user.username == "limited_user"

@pytest.mark.asyncio
async def test_require_permission_no_permission():
    require_perm = require_permission("delete")
    user_instance = DummyUserLimited()
    role = DummyRoleLimited()
    role.permissions = ["read"]
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: delete"

@pytest.mark.asyncio
async def test_require_permission_no_role():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_role_permissions_none():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()
    class RoleWithNonePerms:
        id = 2
        name = "broken"
        permissions = None
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = RoleWithNonePerms()
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_invalid_permission_type():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()
    class RoleInvalidPermType:
        id = 4
        name = "invalidpermtype"
        permissions = 123
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = RoleInvalidPermType()
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: read"

@pytest.mark.asyncio
async def test_require_permission_empty_permission_string():
    require_perm = require_permission("")
    user_instance = DummyUserLimited()
    role = DummyRoleLimited()
    role.permissions = ["read"]
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: "

@pytest.mark.asyncio
async def test_require_permission_permission_not_in_role_permissions():
    require_perm = require_permission("delete")
    user_instance = DummyUserLimited()
    role = DummyRoleLimited()
    role.permissions = ["read", "write"]
    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = role
    db.execute.return_value = mock_result
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Missing required permission: delete"

@pytest.mark.asyncio
async def test_require_permission_admin_integration(async_client, app, async_db_session):
    async def dummy_get_current_user():
        return DummyUser()
    app.dependency_overrides[jwt_get_current_user] = dummy_get_current_user
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
    app.dependency_overrides[jwt_get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = DummyRoleLimited()
    async_db_session.execute.return_value = mock_result
    response = await async_client.get(
        "/test-permission-read",
        headers={"Authorization": "Bearer fake-token"}
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "limited_user"}

@pytest.mark.asyncio
async def test_require_permission_no_permission_integration(async_client, app, async_db_session):
    async def dummy_get_current_user():
        return DummyUserLimited()
    app.dependency_overrides[jwt_get_current_user] = dummy_get_current_user
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = type('Role', (), {"id": 2, "name": "limited", "permissions": ["write"]})
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
    app.dependency_overrides[jwt_get_current_user] = dummy_get_current_user
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
