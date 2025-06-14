# app/api/v1/validators/registration.py
from fastapi import HTTPException
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.registration import Registration


async def ensure_unique_registration_email(email: str, db: AsyncSession) -> None:
    result = await db.execute(select(Registration).where(Registration.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already used for registration.")


async def ensure_unique_registration_username(username: str, db: AsyncSession) -> None:
    result = await db.execute(select(Registration).where(Registration.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already used for registration.")


# app/api/v1/validators/login.py
from fastapi import HTTPException
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User
from app.core.security import verify_password


async def verify_user_credentials(username: str, password: str, db: AsyncSession) -> None:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
