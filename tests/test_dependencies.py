import pytest
from fastapi import HTTPException, status
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError

from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.security.jwt import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.dependencies.auth import get_current_user as auth_get_current_user
from app.api.v1.dependencies.__init__ import get_current_user as init_get_current_user


# --- Test __init__.py coverage missing line (line 27) ---
def test_dependencies_init_get_current_user_function_exists():
    import app.api.v1.dependencies as deps
    # line 27 is get_current_user function export
    assert callable(deps.get_current_user)

def test_dependencies_init_imports():
    import app.api.v1.dependencies as deps
    assert hasattr(deps, "get_current_user")
    # require_permission is NOT exported here
    assert not hasattr(deps, "require_permission")


class DummyUser:
    id = 1
    username = "admin_user"
    role_id = 1  # Admin role

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

class DummyUserLimited:
    id = 2
    username = "limited_user"
    role_id = 2  # Non-admin role

class DummyRoleLimited:
    id = 2
    name = "limited"
    permissions = ["read"]  # limited permissions


@pytest.mark.asyncio
async def test_require_permission_admin():
    require_perm = require_permission("create")
    user_instance = DummyUser()

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = DummyRole()
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    user = await require_perm(user=user_instance, db=db)
    assert user.username == "admin_user"


@pytest.mark.asyncio
async def test_require_permission_has_permission():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = DummyRoleLimited()
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    user = await require_perm(user=user_instance, db=db)
    assert user.username == "limited_user"


@pytest.mark.asyncio
async def test_require_permission_no_permission():
    require_perm = require_permission("delete")
    user_instance = DummyUserLimited()

    role = DummyRoleLimited()
    role.permissions = ["read"]  # does NOT include "delete"

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = role
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_require_permission_no_role():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = None
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Role not found"


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
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = RoleWithNonePerms()
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_require_permission_invalid_permission_type():
    require_perm = require_permission("read")
    user_instance = DummyUserLimited()

    class RoleInvalidPermType:
        id = 4
        name = "invalidpermtype"
        permissions = 123  # Not iterable

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = RoleInvalidPermType()
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()


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
async def test_require_permission_empty_permission_string():
    require_perm = require_permission("")
    user_instance = DummyUser()

    role = DummyRole()
    role.permissions = ["read", "write"]

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = role
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_require_permission_permission_not_in_role_permissions():
    require_perm = require_permission("delete")
    user_instance = DummyUser()

    role = DummyRole()
    role.permissions = ["read", "write"]

    db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()

    mock_scalar_result.first.return_value = role
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()

