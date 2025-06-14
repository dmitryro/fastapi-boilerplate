from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.api.v1.schemas.login import LoginResponse, LoginRequest, Token
from app.api.v1.services.login import LoginService
from app.api.v1.dependencies.permissions import require_permission

router = APIRouter(prefix="", tags=["Logins"])

@router.post("/", response_model=Token)
async def login(
    form_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    token = await LoginService.authenticate_user(form_data.username, form_data.password, db)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

@router.get("/", response_model=List[LoginResponse])
async def read_logins(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    return await LoginService.get_all_logins(db)

@router.get("/{login_id}", response_model=LoginResponse)
async def read_login(
    login_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    login = await LoginService.get_login(login_id, db)
    if not login:
        raise HTTPException(status_code=404, detail="Login not found")
    return login

@router.post("/create", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def create_login(
    login_in: LoginRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("create"))
):
    return await LoginService.create_login(login_in, db)

@router.put("/{login_id}", response_model=LoginResponse)
async def update_login(
    login_id: int,
    login_in: LoginRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("update"))
):
    login = await LoginService.update_login(login_id, login_in, db)
    if not login:
        raise HTTPException(status_code=404, detail="Login not found")
    return login

@router.delete("/{login_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_login(
    login_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("delete"))
):
    deleted = await LoginService.delete_login(login_id, db)
    if not deleted:
        raise HTTPException(status_code=404, detail="Login not found")
    return None

