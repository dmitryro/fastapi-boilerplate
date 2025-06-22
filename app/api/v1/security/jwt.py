from datetime import datetime, timedelta
from typing import Optional
from base64 import b64decode

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.core.db.session import get_db
from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY


bearer_scheme = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, str(SECRET_KEY), algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, str(SECRET_KEY), algorithm=ALGORITHM)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> User:
    # 1. Try Bearer token from OAuth2PasswordBearer
    if token:
        try:
            payload = decode_jwt(token)
            username: str = payload.get("sub")
            if not username:
                raise HTTPException(status_code=401, detail="No subject claim in token")
        except HTTPException:
            # propagate HTTPException raised by decode_jwt
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Bearer token")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    # 2. Try Bearer token from HTTPBearer scheme (optional fallback)
    if bearer and bearer.scheme.lower() == "bearer":
        try:
            payload = decode_jwt(bearer.credentials)
            username: str = payload.get("sub")
            if not username:
                raise HTTPException(status_code=401, detail="No subject claim in token")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Bearer token")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user

    # 3. Try Basic Auth
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("basic "):
        try:
            encoded = auth.split(" ")[1]
            decoded = b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Basic Auth encoding")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user or not user.verify_password(password):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return user

    # Neither Bearer nor Basic Auth provided or valid
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )


def require_permission(permission: str):
    async def role_guard(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(Role).filter(Role.id == user.role_id))
        role = result.scalars().first()
        if role is None:
            raise HTTPException(status_code=403, detail="Role not found")

        # Defensive handling if permissions is None or non-iterable
        perms = role.permissions
        if perms is None:
            raise HTTPException(status_code=403, detail="Permission denied")

        # Check if perms is iterable (but not a string)
        try:
            iter(perms)
        except TypeError:
            raise HTTPException(status_code=403, detail="Permission denied")

        if isinstance(perms, str):
            # Single string, not a list
            perms = [perms]

        if permission not in perms:
            raise HTTPException(status_code=403, detail="Permission denied")

        return user
    return role_guard

