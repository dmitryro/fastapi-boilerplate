from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.models.role import Role as RoleModel

class RoleService:

    @staticmethod
    async def get_all_roles(db: AsyncSession):
        result = await db.execute(select(RoleModel))
        return result.scalars().all()

    @staticmethod
    async def get_role(db: AsyncSession, role_id: int):
        result = await db.execute(select(RoleModel).where(RoleModel.id == role_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def create_role(db: AsyncSession, role_in):
        role = RoleModel(**role_in.dict())
        db.add(role)
        await db.commit()
        await db.refresh(role)
        return role

    @staticmethod
    async def update_role(db: AsyncSession, role_id: int, role_in):
        role = await RoleService.get_role(db, role_id)
        if not role:
            return None
        for key, value in role_in.dict(exclude_unset=True).items():
            setattr(role, key, value)
        await db.commit()
        await db.refresh(role)
        return role

    @staticmethod
    async def delete_role(db: AsyncSession, role_id: int):
        role = await RoleService.get_role(db, role_id)
        if not role:
            return False
        await db.delete(role)
        await db.commit()
        return True

