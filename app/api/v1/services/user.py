from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.v1.models.user import User as UserModel
from app.api.v1.schemas.user import UserCreate, UserUpdate

class UserService:
    @staticmethod
    async def get_all_users(db: AsyncSession) -> List[UserModel]:
        result = await db.execute(select(UserModel))
        return result.scalars().all()

    @staticmethod
    async def get_user(db: AsyncSession, user_id: int) -> Optional[UserModel]:
        result = await db.execute(select(UserModel).where(UserModel.id == user_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> Optional[UserModel]:
        result = await db.execute(select(UserModel).where(UserModel.username == username))
        return result.scalar_one_or_none()

    @staticmethod
    async def create_user(db: AsyncSession, user_in: UserCreate) -> UserModel:
        user = UserModel(**user_in.dict())
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_user(db: AsyncSession, user_id: int, user_in: UserUpdate) -> Optional[UserModel]:
        user = await UserService.get_user(db, user_id)
        if not user:
            return None
        for key, value in user_in.dict(exclude_unset=True).items():
            setattr(user, key, value)
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def delete_user(db: AsyncSession, user_id: int) -> bool:
        user = await UserService.get_user(db, user_id)
        if not user:
            return False
        await db.delete(user)
        await db.commit()
        return True

