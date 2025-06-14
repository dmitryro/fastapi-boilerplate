from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime


class RoleBase(BaseModel):
    name: str
    permissions: List[str] = []


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    permissions: Optional[List[str]] = None


class Role(RoleBase):
    id: int
    created_at: datetime

    model_config = {
        "from_attributes": True  # Pydantic v2 compatible
    }

