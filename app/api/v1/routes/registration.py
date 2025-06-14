from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.api.v1.schemas.registration import Registration, RegistrationCreate, RegistrationUpdate
from app.api.v1.services.registration import RegistrationService
from app.api.v1.dependencies.permissions import require_permission

router = APIRouter(prefix="", tags=["Registrations"])

@router.get("/", response_model=List[Registration])
async def read_registrations(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    return await RegistrationService.get_all_registrations(db)

@router.get("/{registration_id}", response_model=Registration)
async def read_registration(
    registration_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("read"))
):
    registration = await RegistrationService.get_registration(registration_id, db)
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    return registration

@router.post("/", response_model=Registration, status_code=status.HTTP_201_CREATED)
async def create_registration(
    registration_in: RegistrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("create"))
):
    return await RegistrationService.create_registration(registration_in, db)

@router.put("/{registration_id}", response_model=Registration)
async def update_registration(
    registration_id: int,
    registration_in: RegistrationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("update"))
):
    registration = await RegistrationService.update_registration(registration_id, registration_in, db)
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")
    return registration

@router.delete("/{registration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_registration(
    registration_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("delete"))
):
    deleted = await RegistrationService.delete_registration(registration_id, db)
    if not deleted:
        raise HTTPException(status_code=404, detail="Registration not found")
    return None

