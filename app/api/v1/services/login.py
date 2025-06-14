from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.v1.schemas.login import Token, LoginRequest, LoginResponse
from app.api.v1.models.user import User
from app.api.v1.models.login import Login
from app.api.v1.security.jwt import create_access_token
from app.api.v1.services.auth import AuthService

class LoginService:

    @staticmethod
    async def authenticate_user(
        username: str,
        password: str,
        db: AsyncSession
    ) -> Optional[Token]:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            return None

        valid = await AuthService.verify_password(password, user.password)
        if not valid:
            return None

        access_token = create_access_token(
            data={"sub": user.username, "role_id": user.role_id}
        )
        return Token(access_token=access_token, token_type="bearer")

    @staticmethod
    async def get_all_logins(db: AsyncSession) -> List[LoginResponse]:
        result = await db.execute(select(Login))
        logins = result.scalars().all()
        return [LoginResponse.from_orm(login) for login in logins]

    @staticmethod
    async def get_login(login_id: int, db: AsyncSession) -> Optional[LoginResponse]:
        result = await db.execute(select(Login).where(Login.id == login_id))
        login = result.scalar_one_or_none()
        if login:
            return LoginResponse.from_orm(login)
        return None

    @staticmethod
    async def create_login(login_in: LoginRequest, db: AsyncSession) -> LoginResponse:
        new_login = Login(username=login_in.username, password=login_in.password)
        db.add(new_login)
        await db.commit()
        await db.refresh(new_login)
        return LoginResponse.from_orm(new_login)

    @staticmethod
    async def update_login(login_id: int, login_in: LoginRequest, db: AsyncSession) -> Optional[LoginResponse]:
        result = await db.execute(select(Login).where(Login.id == login_id))
        login = result.scalar_one_or_none()
        if not login:
            return None
        login.username = login_in.username
        login.password = login_in.password
        await db.commit()
        await db.refresh(login)
        return LoginResponse.from_orm(login)

    @staticmethod
    async def delete_login(login_id: int, db: AsyncSession) -> bool:
        result = await db.execute(select(Login).where(Login.id == login_id))
        login = result.scalar_one_or_none()
        if not login:
            return False
        await db.delete(login)
        await db.commit()
        return True

