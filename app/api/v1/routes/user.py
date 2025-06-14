from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.api.v1.schemas.user import User, UserCreate, UserUpdate
from app.api.v1.services.user import UserService
from app.api.v1.security.jwt import require_permission

router = APIRouter(prefix="/api/v1/users", tags=["Users"])

@router.get("/", response_model=List[User])
async def read_users(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    return await UserService.get_all_users(db)

@router.get("/{user_id}", response_model=User)
async def read_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    user = await UserService.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("create"))
):
    return await UserService.create_user(db, user_in)

@router.put("/{user_id}", response_model=User)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("update"))
):
    user = await UserService.update_user(db, user_id, user_in)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("delete"))
):
    deleted = await UserService.delete_user(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return None

