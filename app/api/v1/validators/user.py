from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.api.v1.models.user import User
from app.api.v1.models.role import Role # Import Role model for validation

async def ensure_unique_email(email: str, db: AsyncSession) -> None:
    """
    Ensures that the provided email address is unique in the User table.
    Raises HTTPException if the email is already in use.
    """
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use.")


async def ensure_unique_username(username: str, db: AsyncSession) -> None:
    """
    Ensures that the provided username is unique in the User table.
    Raises HTTPException if the username is already taken.
    """
    result = await db.execute(select(User).where(User.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken.")

async def ensure_valid_role_id(role_id: int, db: AsyncSession) -> None:
    """
    Ensures that the provided role_id exists in the Role table.
    Raises HTTPException if the role_id is not found.
    """
    result = await db.execute(select(Role).where(Role.id == role_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Role with ID {role_id} not found.")

def ensure_password_strength(password: str) -> None:
    """
    Ensures the password meets minimum length requirements (at least 8 characters).
    Raises HTTPException if the password is too short.
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

def ensure_username_length(username: str) -> None:
    """
    Ensures the username meets minimum length requirements (at least 3 characters).
    Raises HTTPException if the username is too short.
    """
    if len(username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters long."
        )

def ensure_name_length(name: str, field_name: str) -> None:
    """
    Ensures a given name field (e.g., first name, last name) meets minimum length requirements (at least 2 characters).
    Raises HTTPException if the name is too short.
    """
    if len(name) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be at least 2 characters long."
        )

