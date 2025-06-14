from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional

from app.api.v1.models.registration import Registration
from app.api.v1.schemas.registration import (
    RegistrationCreate,
    RegistrationUpdate,
    Registration as RegistrationSchema
)

class RegistrationService:

    @staticmethod
    async def get_all_registrations(db: AsyncSession) -> List[RegistrationSchema]:
        result = await db.execute(select(Registration))
        return [RegistrationSchema.from_orm(reg) for reg in result.scalars().all()]

    @staticmethod
    async def get_registration(registration_id: int, db: AsyncSession) -> Optional[RegistrationSchema]:
        result = await db.execute(select(Registration).where(Registration.id == registration_id))
        registration = result.scalar_one_or_none()
        return RegistrationSchema.from_orm(registration) if registration else None

    @staticmethod
    async def create_registration(registration_in: RegistrationCreate, db: AsyncSession) -> RegistrationSchema:
        registration = Registration(**registration_in.dict())
        db.add(registration)
        await db.commit()
        await db.refresh(registration)
        return RegistrationSchema.from_orm(registration)

    @staticmethod
    async def update_registration(registration_id: int, registration_in: RegistrationUpdate, db: AsyncSession) -> Optional[RegistrationSchema]:
        result = await db.execute(select(Registration).where(Registration.id == registration_id))
        registration = result.scalar_one_or_none()
        if not registration:
            return None
        for key, value in registration_in.dict(exclude_unset=True).items():
            setattr(registration, key, value)
        await db.commit()
        await db.refresh(registration)
        return RegistrationSchema.from_orm(registration)

    @staticmethod
    async def delete_registration(registration_id: int, db: AsyncSession) -> bool:
        result = await db.execute(select(Registration).where(Registration.id == registration_id))
        registration = result.scalar_one_or_none()
        if not registration:
            return False
        await db.delete(registration)
        await db.commit()
        return True

