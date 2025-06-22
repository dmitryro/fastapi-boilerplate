from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.core.db.session import get_db
from app.api.v1.security.jwt import get_current_user

def require_permission(permission: str):
    async def role_guard(
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ):
        if user.role_id == 1:
            return user

        result = await db.execute(select(Role).where(Role.id == user.role_id))
        role = result.scalar_one_or_none()

        if not role or not isinstance(role.permissions, (list, tuple)) or permission not in role.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}"
            )
        return user

    return role_guard
