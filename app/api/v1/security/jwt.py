from datetime import datetime, timedelta, timezone # <-- Added timezone
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


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    # Use timezone-aware datetime.now(timezone.utc)
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire.timestamp()}) # Convert to Unix timestamp
    return jwt.encode(to_encode, str(SECRET_KEY), algorithm=ALGORITHM)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> User:
    # This exception will be raised if no valid authentication method is found
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )

    # 1. Try Bearer token from OAuth2PasswordBearer (from Authorization header or query/body param)
    if token:
        try:
            payload = jwt.decode(token, str(SECRET_KEY), algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if not username:
                raise ValueError("No sub claim in token")
        except jwt.ExpiredSignatureError: # Specific handling for expired tokens
            raise HTTPException(status_code=401, detail="Token expired", headers={"WWW-Authenticate": "Bearer"})
        except JWTError: # Handles all other JWT errors (e.g., invalid signature)
            raise HTTPException(status_code=401, detail="Invalid Bearer token", headers={"WWW-Authenticate": "Bearer"})

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
        return user

    # 2. Try Bearer token from HTTPBearer scheme (direct Authorization: Bearer header)
    # This block is only entered if `token` (from OAuth2PasswordBearer) was None.
    if bearer and bearer.scheme.lower() == "bearer":
        try:
            payload = jwt.decode(bearer.credentials, str(SECRET_KEY), algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if not username:
                raise ValueError("No sub claim in token")
        except jwt.ExpiredSignatureError: # Specific handling for expired tokens
            raise HTTPException(status_code=401, detail="Token expired", headers={"WWW-Authenticate": "Bearer"})
        except JWTError: # Handles all other JWT errors
            raise HTTPException(status_code=401, detail="Invalid Bearer token", headers={"WWW-Authenticate": "Bearer"})

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
        return user

    # 3. Try Basic Auth
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("basic "):
        try:
            encoded = auth.split(" ")[1]
            decoded = b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception: # This catches ValueError from split or UnicodeDecodeError from decode
            raise HTTPException(status_code=401, detail="Invalid Basic Auth encoding")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user or not user.verify_password(password):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return user

    # Neither Bearer nor Basic Auth provided or valid
    raise credentials_exception


def require_permission(permission: str):
    async def role_guard(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        # If 'permission' is an empty string, or None, deny access immediately.
        # This covers missing line 120 and ensures strict permission validation.
        if not permission: # This is the new line 120 (approx)
            raise HTTPException(status_code=403, detail="Permission denied")

        result = await db.execute(select(Role).filter(Role.id == user.role_id))
        role = result.scalars().first()
        if role is None:
            raise HTTPException(status_code=403, detail="Role not found")

        perms = getattr(role, "permissions", None)

        # Check if perms is iterable (like list, set, tuple, str), else deny permission
        # This complex condition ensures that 'perms' is a list-like object with actual permissions.
        if not perms or not hasattr(perms, "__iter__") or isinstance(perms, (str, bytes)) and len(perms) == 0:
            # Covers None, empty list/tuple/set, non-iterable (e.g., int), or empty string/bytes
            raise HTTPException(status_code=403, detail="Permission denied")

        # print statement for debugging
        print(f"User: {user.username}, Role: {role.name}, Permissions: {perms}")

        # Now safely check membership, wrap in try-except to catch any other unexpected errors
        try:
            if permission not in perms:
                # print statement for debugging
                print(f"Permission '{permission}' missing in {perms}")
                raise HTTPException(status_code=403, detail="Permission denied")
        except TypeError: # This catches if 'perms' unexpectedly becomes non-iterable here
            raise HTTPException(status_code=403, detail="Permission denied")

        return user

    return role_guard

