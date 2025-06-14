from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    first: str
    last: str
    username: str
    email: EmailStr
    phone: Optional[str] = None
    role_id: int


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    first: Optional[str] = None
    last: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    role_id: Optional[int] = None


class User(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True  # Pydantic v2 equivalent of orm_mode
    }

