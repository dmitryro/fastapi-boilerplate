# app/api/v1/validators/registration.py
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.models.registration import Registration


async def ensure_unique_registration_email(email: str, db: AsyncSession) -> None:
    result = await db.execute(select(Registration).where(Registration.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already used for registration.")


async def ensure_unique_registration_username(username: str, db: AsyncSession) -> None:
    result = await db.execute(select(Registration).where(Registration.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already used for registration.")
