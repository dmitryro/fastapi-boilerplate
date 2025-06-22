import pytest
from fastapi import HTTPException, status
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.security import HTTPAuthorizationCredentials
from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.security.jwt import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.dependencies.auth import get_current_user as auth_get_current_user
from app.api.v1.dependencies.__init__ import get_current_user as init_get_current_user


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
    async def mock_get_user():
        return DummyUser()

    async def mock_get_db_with_permission():
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=DummyRole())
                    )
                )
            )
        )
        yield db

    require_perm = require_permission("create")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_with_permission())
    user = await require_perm(user=user_instance, db=db_instance)
    assert user.username == "admin_user"


@pytest.mark.asyncio
async def test_require_permission_has_permission():
    async def mock_get_user():
        return DummyUserLimited()

    async def mock_get_db_with_permission():
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=DummyRoleLimited())
                    )
                )
            )
        )
        yield db

    require_perm = require_permission("read")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_with_permission())
    user = await require_perm(user=user_instance, db=db_instance)
    assert user.username == "limited_user"


@pytest.mark.asyncio
async def test_require_permission_no_permission():
    async def mock_get_user():
        return DummyUserLimited()

    async def mock_get_db_no_permission():
        role = DummyRoleLimited()
        # permissions do NOT include "delete"
        role.permissions = ["read"]

        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=role)
                    )
                )
            )
        )
        yield db

    require_perm = require_permission("delete")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_no_permission())
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db_instance)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    # Permission check message might vary slightly depending on implementation,
    # so we check for 'Permission' and 'denied' in detail message
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_require_permission_no_role():
    async def mock_get_user():
        return DummyUserLimited()

    async def mock_get_db_no_role():
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=None)
                    )
                )
            )
        )
        yield db

    require_perm = require_permission("read")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_no_role())
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db_instance)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Role not found" in exc_info.value.detail


@pytest.mark.asyncio
async def test_require_permission_role_permissions_none():
    async def mock_get_user():
        return DummyUserLimited()

    class RoleWithNonePerms:
        id = 2
        name = "broken"
        permissions = None  # Explicitly None

    async def mock_get_db_permissions_none():
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=RoleWithNonePerms())
                    )
                )
            )
        )
        yield db

    require_perm = require_permission("read")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_permissions_none())
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db_instance)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission" in exc_info.value.detail and "denied" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_auth_get_current_user_valid():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token123")
    db = AsyncMock()

    dummy_user = DummyUser()

    with patch("app.api.v1.dependencies.auth.jwt.decode", return_value={"sub": "admin_user"}):
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=dummy_user)
                    )
                )
            )
        )
        user = await auth_get_current_user(credentials=creds, db=db)
        assert user.username == "admin_user"


@pytest.mark.asyncio
async def test_init_get_current_user_valid():
    db = AsyncMock()
    dummy_user = DummyUser()

    with patch("app.api.v1.dependencies.__init__.jwt.decode", return_value={"sub": "admin_user"}):
        db.execute = AsyncMock(
            return_value=AsyncMock(
                scalars=MagicMock(
                    return_value=MagicMock(
                        first=MagicMock(return_value=dummy_user)
                    )
                )
            )
        )

        # Patch SECRET_KEY to a mock that has .get_secret_value()
        class MockSecret:
            def get_secret_value(self):
                return "dummysecret"

        with patch("app.api.v1.dependencies.__init__.SECRET_KEY", new=MockSecret()):
            user = await init_get_current_user(token="any.jwt.token", db=db)
            assert user.username == "admin_user"
