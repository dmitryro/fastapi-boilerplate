# app/api/v1/validators/login.py
from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.models.user import User
from app.api.v1.schemas.login import LoginRequest
from app.api.v1.services.auth import AuthService


async def verify_user_credentials(username: str, password: str, db: AsyncSession) -> None:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not await AuthService.verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")


def validate_login(data: dict) -> LoginRequest:
    """
    Validate login data against the LoginRequest schema and ensure password is at least 8 characters long.
    """
    if len(data.get("password", "")) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters long",
        )
    try:
        login = LoginRequest(**data)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    return login
