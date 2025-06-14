from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api.v1.schemas.registration import RegistrationSchema, RegistrationResponse
from app.api.v1.schemas.login import TokenResponse
from app.api.v1.models.user import User
from app.api.v1.models.registration import Registration
from app.api.v1.models.login import Login
from app.api.v1.security.jwt import create_access_token
from app.core.db.session import get_db

pwd_context = PasswordHasher()


class AuthService:
    def __init__(self, db: AsyncSession = Depends(get_db)):
        self.db = db

    async def register_user(self, reg: RegistrationSchema) -> RegistrationResponse:
        query = await self.db.execute(select(User).where(User.username == reg.username))
        existing = query.scalars().first()
        if existing:
            raise Exception("Username already exists")

        hashed_pw = pwd_context.hash(reg.password)
        new_user = User(
            first=reg.first,
            last=reg.last,
            username=reg.username,
            email=reg.email,
            password=hashed_pw,
            phone=reg.phone,
            role_id=reg.role_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)


        registration_record = Registration(
            first=new_user.first,
            last=new_user.last,
            username=new_user.username,
            email=new_user.email,
            password=hashed_pw,
            phone=new_user.phone,
            role_id=new_user.role_id
        )
        self.db.add(registration_record)
        await self.db.commit()

        return RegistrationResponse.from_orm(new_user)

    @staticmethod
    async def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            pwd_context.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

    async def authenticate_user(self, username: str, password: str) -> User | None:
        query = await self.db.execute(select(User).where(User.username == username))
        user = query.scalars().first()
        if not user:
            return None
        if not await AuthService.verify_password(password, user.password):
            return None
        return user

    async def create_token_response(self, user: User, plain_password: str) -> TokenResponse:
        token = create_access_token(
            data={"sub": user.username, "role_id": user.role_id}
        )

        hashed_pw = pwd_context.hash(plain_password)
        login_record = Login(
            username=user.username,
            password=hashed_pw,
            login_time=datetime.utcnow()
        )
        self.db.add(login_record)
        await self.db.commit()

        return TokenResponse(access_token=token)

