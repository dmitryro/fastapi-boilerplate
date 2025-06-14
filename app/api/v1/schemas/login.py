from pydantic import BaseModel, constr
from datetime import datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3)
    password: constr(min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    id: int
    username: str
    login_time: datetime

    class Config:
        from_attributes = True  # Updated for Pydantic V2

