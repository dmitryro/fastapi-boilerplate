from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from app.api.v1.services.auth import AuthService
from app.api.v1.schemas.login import TokenResponse
from app.api.v1.schemas.registration import RegistrationSchema, RegistrationResponse
from app.api.v1.models.user import User
from app.core.db.session import get_db
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="", tags=["auth"])

@router.post("/register", response_model=RegistrationResponse, status_code=status.HTTP_201_CREATED)
async def register(
    reg: RegistrationSchema,
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db=db)
    return await auth_service.register_user(reg)

@router.post("/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db=db)
    user = await auth_service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await auth_service.create_token_response(user, form_data.password)
