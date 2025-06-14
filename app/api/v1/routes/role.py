from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.api.v1.schemas.role import Role, RoleCreate, RoleUpdate
from app.api.v1.services.role import RoleService
from app.api.v1.security.jwt import require_permission

router = APIRouter(prefix="", tags=["Roles"])

@router.get("/", response_model=List[Role])
async def read_roles(
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("read"))
):
    return await RoleService.get_all_roles(db)

@router.get("/{role_id}", response_model=Role)
async def read_role(
    role_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("read"))
):
    role = await RoleService.get_role(db, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@router.post("/", response_model=Role, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_in: RoleCreate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("create"))
):
    return await RoleService.create_role(db, role_in)

@router.put("/{role_id}", response_model=Role)
async def update_role(
    role_id: int,
    role_in: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("update"))
):
    role = await RoleService.update_role(db, role_id, role_in)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("delete"))
):
    deleted = await RoleService.delete_role(db, role_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Role not found")
    return None

