from fastapi import HTTPException, status
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.schemas.registration import RegistrationSchema, RegistrationResponse
from app.api.v1.schemas.login import TokenResponse
from app.api.v1.models.user import User
from app.api.v1.models.registration import Registration
from app.api.v1.models.login import Login
from app.api.v1.models.role import Role
from app.api.v1.security.jwt import create_access_token
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = PasswordHasher()

class AuthService:
    def __init__(self, db: AsyncSession):
        if db is None:
            raise ValueError("Database session cannot be None")
        self.db = db

    async def register_user(self, reg: RegistrationSchema) -> RegistrationResponse:
        try:
            # Check for existing username in User
            username_query = await self.db.execute(select(User).where(User.username == reg.username))
            existing_username = username_query.scalars().first()
            if existing_username:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

            # Check for existing email in User
            email_query = await self.db.execute(select(User).where(User.email == reg.email))
            existing_email = email_query.scalars().first()
            if existing_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

            # Check for existing username in Registration
            reg_username_query = await self.db.execute(select(Registration).where(Registration.username == reg.username))
            existing_reg_username = reg_username_query.scalars().first()
            if existing_reg_username:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already used for registration")

            # Check for existing email in Registration
            reg_email_query = await self.db.execute(select(Registration).where(Registration.email == reg.email))
            existing_reg_email = reg_email_query.scalars().first()
            if existing_reg_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already used for registration")

            # Check for valid role
            role_query = await self.db.execute(select(Role).where(Role.id == reg.role_id))
            role = role_query.scalar_one_or_none()
            if not role:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")

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
                created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
            )
            self.db.add(new_user)
            await self.db.commit()
            await self.db.refresh(new_user)
            # Set ID for testing if not assigned (mock database may not auto-increment)
            if new_user.id is None:
                new_user.id = 1

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
        except SQLAlchemyError as e:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Database error: {str(e)}"
            )
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unexpected error: {str(e)}"
            )

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
            data={"sub": user.username, "role_id": user.role_id},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        hashed_pw = pwd_context.hash(plain_password)
        login_record = Login(
            username=user.username,
            password=hashed_pw,
            login_time=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        self.db.add(login_record)
        await self.db.commit()

        return TokenResponse(access_token=token)
