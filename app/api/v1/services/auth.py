from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api.v1.schemas.registration import RegistrationSchema, RegistrationResponse
from app.api.v1.schemas.login import TokenResponse
from app.api.v1.models.user import User
from app.api.v1.models.registration import Registration
from app.api.v1.models.login import Login
from app.api.v1.models.role import Role
from app.api.v1.security.jwt import create_access_token
from app.core.db.session import get_db


# Optional: you can define these in a shared exceptions module
class UsernameAlreadyExists(Exception):
    pass

class EmailAlreadyExists(Exception):
    pass

class RoleNotFound(Exception):
    pass


pwd_context = PasswordHasher()


class AuthService:
    def __init__(self, db: AsyncSession = Depends(get_db)):
        self.db = db

    async def register_user(self, reg: RegistrationSchema) -> RegistrationResponse:
        # Check for existing username
        username_query = await self.db.execute(select(User).where(User.username == reg.username))
        existing_username = username_query.scalars().first()
        if existing_username:
            raise Exception("Username already exists")

        # Check for existing email
        email_query = await self.db.execute(select(User).where(User.email == reg.email))
        existing_email = email_query.scalars().first()
        if existing_email:
            raise Exception("Email already exists")

        # Check for valid role
        role_query = await self.db.execute(select(Role).where(Role.id == reg.role_id))
        role = role_query.scalar_one_or_none()
        if not role:
            raise Exception("Role not found")

        # Proceed to create user
        hashed_pw = pwd_context.hash(reg.password)
        new_user = User(
            first=reg.first,
            last=reg.last,
            username=reg.username,
            email=reg.email,
            password=hashed_pw,
            phone=reg.phone,
            role_id=reg.role_id,
            created_at=datetime.utcnow(), # These datetimes are timezone-naive
            updated_at=datetime.utcnow(), # These datetimes are timezone-naive
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
            # Fix: Convert timezone-aware datetime to timezone-naive for TIMESTAMP WITHOUT TIME ZONE
            login_time=datetime.now(timezone.utc).replace(tzinfo=None) 
        )
        self.db.add(login_record)
        await self.db.commit()

        return TokenResponse(access_token=token)

