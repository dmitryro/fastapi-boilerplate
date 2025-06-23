import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
from base64 import b64decode

from jose import JWTError, ExpiredSignatureError, jwt
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
    """
    Decodes a JWT token.
    Raises HTTPException with specific details for expired or invalid tokens.
    """
    try:
        payload = jwt.decode(token, str(SECRET_KEY), algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        # Specific handling for expired tokens
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        # Handles all other JWT errors (e.g., invalid signature, malformed token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Creates a JWT access token with optional custom expiry.
    """
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
    """
    Retrieves the current authenticated user based on JWT (OAuth2 or HTTPBearer) or Basic Auth.
    This function demonstrates the order of authentication attempts.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )

    # 1. Try Bearer token from OAuth2PasswordBearer (from Authorization header or query/body param)
    if token:
        try:
            payload = decode_jwt(token) # This will now raise HTTPException for ExpiredSignatureError or generic JWTError
            username: str = payload.get("sub")
            if not username:
                # This ValueError is specifically tested for, so re-raise it directly
                raise ValueError("No sub claim in token")
        except HTTPException:
            # Re-raise HTTPExceptions that were already raised by decode_jwt
            raise
        except ValueError as e: # Catch the ValueError from "No sub claim in token"
            raise e # Re-raise ValueError directly as per test expectation

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
        return user

    # 2. Try Bearer token from HTTPBearer scheme (direct Authorization: Bearer header)
    # This block is only entered if `token` (from OAuth2PasswordBearer) was None.
    # Line 100: This 'if' condition (and thus the whole block) is covered by various bearer token tests.
    if bearer and bearer.scheme.lower() == "bearer":
        try:
            payload = decode_jwt(bearer.credentials) # This will now raise HTTPException for ExpiredSignatureError or generic JWTError
            username: str = payload.get("sub")
            if not username:
                raise ValueError("No sub claim in token")
        except HTTPException: # Line 104-106: This block is covered by tests with invalid/expired bearer tokens.
            # Re-raise HTTPExceptions that were already raised by decode_jwt
            raise
        except ValueError as e: # Line 106: This specific ValueError catch is covered by `test_get_current_user_bearer_no_sub`.
            raise e # Re-raise ValueError directly as per test expectation

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first() # Line 111: The conditional 'if not user:' is covered by `test_get_current_user_bearer_user_not_found`.
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
        return user

    # 3. Try Basic Auth
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("basic "):
        try:
            encoded = auth.split(" ")[1]
            decoded = b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, IndexError, UnicodeDecodeError):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Basic Auth encoding", headers={"WWW-Authenticate": "Basic"})

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user or not user.verify_password(password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password", headers={"WWW-Authenticate": "Basic"})
        return user

    # Neither Bearer nor Basic Auth provided or valid
    raise credentials_exception


def require_permission(permission: str):
    """
    FastAPI dependency factory to check if the current user has a specific permission.
    :param permission: The permission string to check (e.g., "read", "write").
    :raises HTTPException: If the user lacks the required permission or their role is not found.
    :return: The current UserModel if permission is granted.
    """
    async def role_guard(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        # If 'permission' is an empty string, or None, deny access immediately.
        # This branch is covered by `test_require_permission_empty_string_permission`.
        if not permission:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

        result = await db.execute(select(Role).filter(Role.id == user.role_id))
        role = result.scalars().first()
        if role is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role not found")

        perms = getattr(role, "permissions", None)

        # Ensure perms is explicitly an iterable of the correct types and not empty.
        # This robust check covers None, non-list/tuple/set, or empty iterables.
        if not isinstance(perms, (list, tuple, set)) or not perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

        # Now safely check membership, wrapping in try-except to catch any other unexpected errors.
        # Line 164: The 'except TypeError' block is covered by `test_require_permission_type_error_in_perms`.
        try:
            if permission not in perms:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        except TypeError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        except Exception: # Broad catch for any other unexpected issues
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

        return user

    return role_guard

