import pytest
from fastapi import HTTPException, status
from unittest.mock import AsyncMock
from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.security.jwt import require_permission
from sqlalchemy.ext.asyncio import AsyncSession


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
            return_value=type(
                "Result",
                (),
                {
                    "scalars": lambda *args, **kwargs: type(
                        "Scalars", (), {"first": lambda *a, **kw: DummyRole()}
                    )(),
                },
            )()
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
            return_value=type(
                "Result",
                (),
                {
                    "scalars": lambda *args, **kwargs: type(
                        "Scalars", (), {"first": lambda *a, **kw: DummyRoleLimited()}
                    )(),
                },
            )()
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
            return_value=type(
                "Result",
                (),
                {
                    "scalars": lambda *args, **kwargs: type(
                        "Scalars", (), {"first": lambda *a, **kw: role}
                    )(),
                },
            )()
        )
        yield db

    require_perm = require_permission("delete")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_no_permission())
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db_instance)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission denied" in exc_info.value.detail


@pytest.mark.asyncio
async def test_require_permission_no_role():
    async def mock_get_user():
        return DummyUserLimited()

    async def mock_get_db_no_role():
        db = AsyncMock(spec=AsyncSession)
        db.execute = AsyncMock(
            return_value=type(
                "Result",
                (),
                {
                    "scalars": lambda *args, **kwargs: type(
                        "Scalars", (), {"first": lambda *a, **kw: None}
                    )(),
                },
            )()
        )
        yield db

    require_perm = require_permission("read")

    user_instance = await mock_get_user()
    db_instance = await anext(mock_get_db_no_role())
    with pytest.raises(HTTPException) as exc_info:
        await require_perm(user=user_instance, db=db_instance)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Role not found" in exc_info.value.detail

