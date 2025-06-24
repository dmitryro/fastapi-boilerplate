from pydantic import BaseModel, EmailStr, constr
from typing import Optional
from datetime import datetime


class RegistrationBase(BaseModel):
    first: str
    last: str
    username: str
    email: EmailStr
    password: constr(min_length=8)
    phone: Optional[str] = None
    role_id: int


# Used for internal validation where stricter constraints are required
class RegistrationCreate(RegistrationBase):
    password: constr(min_length=8)


# Optional fields for update scenarios
class RegistrationUpdate(BaseModel):
    first: Optional[str]
    last: Optional[str]
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]
    phone: Optional[str]
    role_id: Optional[int]


# Used in responses to the client
class RegistrationResponse(BaseModel):
    id: int
    first: str
    last: str
    username: str
    email: str
    phone: Optional[str] = None
    role_id: int
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True  # Pydantic v2 orm_mode equivalent
    }


class Registration(RegistrationBase):
    id: int
    created_at: Optional[datetime]

    class Config:
        from_attributes = True  # pydantic v2 replacement of orm_mode

RegistrationSchema = RegistrationBase

