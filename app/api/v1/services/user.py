from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status # Import HTTPException and status for consistent error handling

from app.api.v1.models.user import User as UserModel
from app.api.v1.schemas.user import UserCreate, UserUpdate
from app.api.v1.security.passwords import hash_password # Import hash_password utility
from app.api.v1.validators.user import (
    ensure_unique_email,
    ensure_unique_username,
    ensure_valid_role_id,
    ensure_password_strength, # New import
    ensure_username_length,   # New import
    ensure_name_length        # New import
)

class UserService:
    @staticmethod
    async def get_all_users(db: AsyncSession) -> List[UserModel]:
        """
        Retrieves all user records from the database.
        """
        result = await db.execute(select(UserModel))
        return result.scalars().all()

    @staticmethod
    async def get_user(db: AsyncSession, user_id: int) -> Optional[UserModel]:
        """
        Retrieves a single user record by its ID.
        """
        result = await db.execute(select(UserModel).where(UserModel.id == user_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> Optional[UserModel]:
        """
        Retrieves a single user record by its username.
        """
        result = await db.execute(select(UserModel).where(UserModel.username == username))
        return result.scalar_one_or_none()

    @staticmethod
    async def create_user(db: AsyncSession, user_in: UserCreate) -> UserModel:
        """
        Creates a new user record in the database after performing validations.
        Includes password hashing.
        """
        # --- Pre-creation Validation ---
        # Ensure email and username are unique
        await ensure_unique_email(user_in.email, db)
        await ensure_unique_username(user_in.username, db)
        # Ensure role_id is valid
        await ensure_valid_role_id(user_in.role_id, db)
        # Ensure password strength
        ensure_password_strength(user_in.password) # No await, as it's a synchronous function
        # Ensure username length
        ensure_username_length(user_in.username)   # No await
        # Ensure first and last name lengths
        ensure_name_length(user_in.first, "First name") # No await
        ensure_name_length(user_in.last, "Last name")   # No await

        # Create a new user instance, hashing the password
        new_user = UserModel(
            first=user_in.first,
            last=user_in.last,
            email=user_in.email,
            username=user_in.username,
            password=hash_password(user_in.password), # Hash the password before storing
            phone=user_in.phone,
            role_id=user_in.role_id
        )

        try:
            db.add(new_user)
            await db.commit()
            await db.refresh(new_user) # Refresh to populate generated fields like 'id' and timestamps
            return new_user
        except Exception as e:
            await db.rollback() # Rollback in case of any database error during commit/refresh
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create user due to a database error: {e}"
            )

    @staticmethod
    async def update_user(db: AsyncSession, user_id: int, user_in: UserUpdate) -> Optional[UserModel]:
        """
        Updates an existing user record.
        Includes checks for unique email/username if they are being updated.
        """
        user = await UserService.get_user(db, user_id)
        if not user:
            return None # User not found, return None

        # --- Pre-update Validation ---
        # Check for unique email if email is being updated
        if user_in.email is not None and user_in.email != user.email:
            await ensure_unique_email(user_in.email, db)
        
        # Check for unique username if username is being updated
        if user_in.username is not None and user_in.username != user.username:
            await ensure_unique_username(user_in.username, db)
            ensure_username_length(user_in.username) # Apply length validation on update
        else: # If username is not explicitly updated but exists, ensure its current length is valid (edge case)
            ensure_username_length(user.username)

        # Check for valid role_id if role_id is being updated
        if user_in.role_id is not None and user_in.role_id != user.role_id:
            await ensure_valid_role_id(user_in.role_id, db)

        # Update user attributes
        for key, value in user_in.dict(exclude_unset=True).items():
            if key == "password" and value is not None:
                # Hash new password if provided, and ensure strength
                ensure_password_strength(value) # Apply strength validation on update
                setattr(user, key, hash_password(value))
            elif key == "first" and value is not None:
                ensure_name_length(value, "First name") # Apply length validation on update
                setattr(user, key, value)
            elif key == "last" and value is not None:
                ensure_name_length(value, "Last name") # Apply length validation on update
                setattr(user, key, value)
            else:
                setattr(user, key, value)
        
        try:
            await db.commit()
            await db.refresh(user) # Refresh to reflect changes and update 'updated_at'
            return user
        except Exception as e:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to update user due to a database error: {e}"
            )

    @staticmethod
    async def delete_user(db: AsyncSession, user_id: int) -> bool:
        """
        Deletes a user record by its ID.
        """
        user = await UserService.get_user(db, user_id)
        if not user:
            return False # User not found

        try:
            await db.delete(user)
            await db.commit()
            return True
        except Exception as e:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete user due to a database error: {e}"
            )

