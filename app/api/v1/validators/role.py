from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.role import Role


async def ensure_role_exists(role_id: int, db: AsyncSession) -> Role:
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail=f"Role ID {role_id} does not exist.")
    return role


async def ensure_unique_role_name(name: str, db: AsyncSession) -> None:
    result = await db.execute(select(Role).where(Role.name == name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Role with name '{name}' already exists.")

