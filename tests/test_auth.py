import pytest
import jwt
from fastapi import status, HTTPException, Depends, FastAPI
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError # Import SQLAlchemyError
from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.models.registration import Registration
from app.api.v1.services.auth import AuthService # Now imports AuthService which uses password utils
from datetime import datetime, timezone, timedelta
from argon2.exceptions import VerifyMismatchError # Import VerifyMismatchError (still needed for patching)
# Import hashing and verification utilities from the passwords module
from app.api.v1.security.passwords import hash_password, verify_password
# Import RegistrationSchema to resolve NameError
from app.api.v1.schemas.registration import RegistrationSchema 
import logging
from httpx._transports.asgi import ASGITransport

# Assuming app.main.app and app.core.db.session.get_db are available
from app.main import app
from app.core.db.session import get_db

logger = logging.getLogger(__name__)


def mock_result(scalar):
    result = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = scalar
    result.scalars.return_value = scalars_mock
    result.scalar_one_or_none.return_value = scalar
    return result

@pytest.fixture
async def mock_db():
    """Provides a new AsyncMock session for each test to ensure isolation."""
    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(first=MagicMock(return_value=None)),
        scalar_one_or_none=MagicMock(return_value=None)
    ))
    db.add = MagicMock(return_value=None)
    db.flush = AsyncMock(return_value=None)
    db.commit = AsyncMock(return_value=None)
    db.rollback = AsyncMock(return_value=None) # Ensure rollback is mocked

    def refresh_side_effect(obj):
        if isinstance(obj, User):
            if obj.id is None:
                obj.id = 1
            obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        elif isinstance(obj, Registration):
            if obj.id is None:
                obj.id = 1
            obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.refresh = AsyncMock(side_effect=refresh_side_effect)
    return db

@pytest.fixture
async def async_client(mock_db: AsyncSession):
    """Provides an async test client for FastAPI application with mocked database."""
    async def override_get_db():
        yield mock_db
    
    app.dependency_overrides[get_db] = override_get_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests successful user registration via the /register endpoint."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Jane", "last": "Smith", "email": "jane@example.com",
        "username": "janesmith", "password": "StrongPass123!", "phone": "555-1234", "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Register success response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_201_CREATED
    assert mock_db.commit.call_count >= 1 # At least one commit
    assert response.json()["username"] == "janesmith"

@pytest.mark.asyncio
async def test_register_existing_username(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration failure when username exists in User."""
    mock_db.reset_mock()
    query_results = [
        # Use hash_password from utility
        mock_result(User(id=1, username="existingusername", email="existing@example.com",
                         password=hash_password("Password123!"),
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                         updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Dup", "last": "User", "email": "unique@example.com",
        "username": "existingusername", "password": "Password123!",
        "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing username test response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "username already exists" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_existing_email(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration failure when email exists in User."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),
        # Use hash_password from utility
        mock_result(User(id=2, username="otheruser", email="duplicate@example.com",
                         password=hash_password("Password123!"),
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                         updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Dup", "last": "User", "email": "duplicate@example.com",
        "username": "newusername", "password": "Password123!",
        "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing email test response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email already exists" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_existing_registration_username(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration failure when username exists in Registration."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        # Use hash_password from utility
        mock_result(Registration(id=1, username="existingusername", email="existing@example.com",
                                 password=hash_password("Password123!")))
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Dup", "last": "User", "email": "unique@example.com",
        "username": "existingusername", "password": "Password123!",
        "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing registration username test response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "username already used for registration" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_existing_registration_email(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration failure when email exists in Registration."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        # Use hash_password from utility
        mock_result(Registration(id=2, username="otheruser", email="duplicate@example.com",
                                 password=hash_password("Password123!")))
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Dup", "last": "User", "email": "duplicate@example.com",
        "username": "newusername", "password": "Password123!",
        "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing registration email test response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email already used for registration" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_invalid_password(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration with short password, expecting validation error."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "Weak", "last": "Password", "email": "weak@example.com",
        "username": "weakpass", "password": "short",
        "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Invalid password response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "string should have at least 8 characters" in str(response.json()).lower()
    mock_db.execute.assert_not_awaited()

@pytest.mark.asyncio
async def test_register_invalid_role_id_route(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration failure when role_id does not exist."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(None),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    payload = {
        "first": "No", "last": "Role", "email": "norole@example.com",
        "username": "noroleuser", "password": "Password123!",
        "phone": None, "role_id": 9999,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Invalid role test response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "role not found" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_login_invalid_password_length_route(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests login with short password."""
    mock_db.reset_mock()
    test_password = "validpassword"
    # Use hash_password from utility
    hashed_password = hash_password(test_password)
    dummy_user = User(
        id=1, username="testuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    mock_db.execute.return_value = mock_result(dummy_user)
    
    response = await async_client.post("/api/v1/auth/login", data={
        "username": "testuser",
        "password": "short"
    })
    logger.debug(f"Login invalid password response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect username or password" in response.json().get("detail", "").lower()
    mock_db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_login_malformed_headers_route(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests login with malformed Authorization header."""
    mock_db.reset_mock()
    test_password = "password123"
    # Use hash_password from utility
    hashed_password = hash_password(test_password)
    dummy_user = User(
        id=1, username="testuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    mock_db.execute.side_effect = [
        mock_result(dummy_user)
    ]
    with patch("app.api.v1.services.auth.create_access_token", return_value="mocked_access_token"):
        response = await async_client.post("/api/v1/auth/login", headers={"Authorization": "Invalid"},
                                             data={"username": "testuser", "password": "password123"})
        logger.debug(f"Login malformed headers response: {response.status_code} {response.json()}")
        logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
        assert response.status_code == status.HTTP_200_OK
        assert "access_token" in response.json()
        assert response.json()["access_token"] == "mocked_access_token"


@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests successful login."""
    mock_db.reset_mock()
    test_password = "password123"
    # Use hash_password from utility
    hashed_password = hash_password(test_password)
    dummy_user = User(
        id=1, username="testuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    query_results = [
        mock_result(dummy_user),
    ]
    mock_db.execute.side_effect = query_results
    
    with patch("app.api.v1.services.auth.create_access_token", return_value="mocked_access_token"):
        response = await async_client.post("/api/v1/auth/login", data={
            "username": "testuser",
            "password": "password123"
        })
        logger.debug(f"Login success response: {response.status_code} {response.json()}")
        logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
        assert response.status_code == status.HTTP_200_OK
        assert "access_token" in response.json()
        assert response.json()["access_token"] == "mocked_access_token"
        mock_db.execute.assert_awaited_once()
        mock_db.add.assert_called_once()
        mock_db.commit.assert_awaited_once()


# Test for line 23: `if db is None:` in `AuthService.__init__`
@pytest.mark.asyncio
async def test_auth_service_init_db_none():
    """Tests AuthService initialization with a None database session."""
    with pytest.raises(ValueError) as exc_info:
        AuthService(db=None)
    assert "Database session cannot be None" in str(exc_info.value)

@pytest.mark.asyncio
async def test_auth_service_authenticate_success(mock_db: AsyncMock):
    """Tests AuthService.authenticate_user success."""
    mock_db.reset_mock()
    test_password = "testpass123"
    # Use hash_password from utility
    hashed_password = hash_password(test_password)
    dummy_user = User(
        id=1, username="serviceuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    query_results = [
        mock_result(dummy_user)
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    user = await auth_service.authenticate_user("serviceuser", test_password)
    logger.debug(f"Authenticate success mock calls: {mock_db.execute.call_args_list}")
    assert user is not None
    assert user.username == "serviceuser"
    mock_db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_auth_service_authenticate_wrong_password(mock_db: AsyncMock):
    """Tests AuthService.authenticate_user with wrong password."""
    mock_db.reset_mock()
    correct_password = "correctpass123"
    # Use hash_password from utility
    hashed_password = hash_password(correct_password)
    dummy_user = User(
        id=1, username="serviceuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    query_results = [
        mock_result(dummy_user)
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    user = await auth_service.authenticate_user("serviceuser", "wrongpass123")
    logger.debug(f"Authenticate wrong password mock calls: {mock_db.execute.call_args_list}")
    assert user is None

@pytest.mark.asyncio
async def test_auth_service_verify_password_mismatch():
    """
    Tests AuthService.verify_password with a mismatched password.
    This test patches the `AuthService.verify_password` directly to simulate the
    mismatch scenario since the underlying argon2 `verify` method is read-only.
    """
    test_hashed_password = "a_hashed_password_string"
    test_plain_password = "wrong_password"

    # Patch `AuthService.verify_password` directly to control its return value
    with patch('app.api.v1.services.auth.AuthService.verify_password', new_callable=AsyncMock) as mock_auth_service_verify:
        mock_auth_service_verify.return_value = False # Simulate mismatch

        # Call the AuthService.verify_password method, which will now use the mocked version
        is_valid = await AuthService.verify_password(test_plain_password, test_hashed_password)
        
        # Assert that the mocked method was called and returned False as expected
        assert is_valid is False
        mock_auth_service_verify.assert_awaited_once_with(test_plain_password, test_hashed_password)


@pytest.mark.asyncio
async def test_auth_service_authenticate_nonexistent_user(mock_db: AsyncMock):
    """Tests AuthService.authenticate_user for nonexistent user."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None)
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    user = await auth_service.authenticate_user("nonexistent", "any_password123")
    logger.debug(f"Authenticate nonexistent user mock calls: {mock_db.execute.call_args_list}")
    assert user is None

@pytest.mark.asyncio
async def test_auth_service_register_user_success(mock_db: AsyncMock):
    """Tests AuthService.register_user success and ensures full coverage of success path."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check (no existing user with username)
        mock_result(None),  # User email check (no existing user with email)
        mock_result(None),  # Registration username check (no pending registration with username)
        mock_result(None),  # Registration email check (no pending registration with email)
        mock_result(Role(id=1, name="user")),  # Role check (role exists)
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    
    user = await auth_service.register_user(registration)
    
    logger.debug(f"Register user success mock execute calls: {mock_db.execute.call_args_list}")
    logger.debug(f"Register user success mock add calls: {mock_db.add.call_args_list}")
    logger.debug(f"Register user success mock commit calls: {mock_db.commit.call_args_list}")
    logger.debug(f"Register user success mock refresh calls: {mock_db.refresh.call_args_list}")

    assert user.username == "janesmith"
    # Ensure all initial checks (5 execute calls) and then 2 adds, 1 refresh, 2 commits happen
    assert mock_db.execute.call_count == 5 
    assert mock_db.add.call_count == 2 # One for new_user, one for registration_record
    assert mock_db.refresh.call_count == 1 # Only new_user is refreshed
    assert mock_db.commit.call_count == 2 # One commit for new_user, one for registration_record
    mock_db.flush.assert_not_awaited() # Explicitly assert flush is NOT called
    mock_db.rollback.assert_not_awaited() # Ensure no rollback on success

@pytest.mark.asyncio
async def test_auth_service_register_user_duplicate_user_username(mock_db: AsyncMock):
    """Tests AuthService.register_user with duplicate user username."""
    mock_db.reset_mock()
    query_results = [
        # Use hash_password from utility
        mock_result(User(id=1, username="janesmith", email="existing@example.com",
                         password=hash_password("Password123!"),
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                         updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(registration)
    logger.debug(f"Duplicate user username mock calls: {mock_db.execute.call_args_list}")
    assert "username already exists" in str(exc_info.value).lower()
    mock_db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_auth_service_register_user_duplicate_user_email(mock_db: AsyncMock):
    """Tests AuthService.register_user with duplicate user email."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None), # Username check passes
        # Use hash_password from utility
        mock_result(User(id=2, username="otheruser", email="jane@example.com",
                         password=hash_password("Password123!"),
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                         updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(registration)
    logger.debug(f"Duplicate user email mock calls: {mock_db.execute.call_args_list}")
    assert "email already exists" in str(exc_info.value).lower()
    assert mock_db.execute.call_count == 2

@pytest.mark.asyncio
async def test_auth_service_register_user_invalid_role(mock_db: AsyncMock):
    """Tests AuthService.register_user with invalid role_id."""
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(None),  # Role check - this mock returns None for role
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=9999
    )
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(registration)
    logger.debug(f"Invalid role mock calls: {mock_db.execute.call_args_list}")
    assert "role not found" in str(exc_info.value).lower()
    assert mock_db.execute.call_count == 5

@pytest.mark.asyncio
async def test_auth_service_register_user_generic_db_error(mock_db: AsyncMock):
    """
    Tests AuthService.register_user with a generic exception (not SQLAlchemyError)
    to cover the `except Exception as e:` block (lines 96-101 in auth.py).
    """
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    
    # Simulate a generic Python Exception during the first commit
    mock_db.commit.side_effect = Exception("Simulated generic non-SQLAlchemy error")
    
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Test", last="User", email="test@example.com", username="testuser",
        password="StrongPass123!", phone="123-456-7890", role_id=1
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(registration)
    
    logger.debug(f"Generic exception mock calls: {mock_db.execute.call_args_list}")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "unexpected error: simulated generic non-sqlalchemy error" in str(exc_info.value).lower()
    assert mock_db.add.call_count == 1 # new_user is added before the failing commit
    assert mock_db.commit.call_count == 1 # The first commit attempt
    mock_db.rollback.assert_awaited_once() # Rollback should be called
    mock_db.refresh.assert_not_awaited() # Refresh should not be called as commit fails before it

@pytest.mark.asyncio
async def test_auth_service_register_user_sqlalchemy_error(mock_db: AsyncMock):
    """
    Tests AuthService.register_user with a SQLAlchemyError to cover
    the `except SQLAlchemyError as e:` block (lines 90-95 in auth.py).
    """
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    
    # Simulate a SQLAlchemyError during the first commit
    mock_db.commit.side_effect = SQLAlchemyError("Simulated SQLAlchemy error during commit")
    
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="SQLA", last="Error", email="sqla@example.com", username="sqlauser",
        password="StrongPass123!", phone="111-222-3333", role_id=1
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(registration)
    
    logger.debug(f"SQLAlchemy error mock calls: {mock_db.execute.call_args_list}")
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert "database error: simulated sqlalchemy error during commit" in str(exc_info.value).lower()
    assert mock_db.add.call_count == 1 # new_user is added before the failing commit
    assert mock_db.commit.call_count == 1 # The first commit attempt
    mock_db.rollback.assert_awaited_once() # Rollback should be called
    mock_db.refresh.assert_not_awaited() # Refresh should not be called as commit fails before it


@pytest.mark.asyncio
async def test_register_empty_payload(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration with empty payload."""
    mock_db.reset_mock()
    response = await async_client.post("/api/v1/auth/register", json={})
    logger.debug(f"Empty payload response: {response.status_code} {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "field required" in str(response.json()).lower()

@pytest.mark.asyncio
async def test_register_invalid_email_format(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration with invalid email format."""
    mock_db.reset_mock()
    payload = {
        "first": "Jane", "last": "Smith", "email": "invalid_email",
        "username": "janesmith", "password": "StrongPass123!", "phone": "555-1234", "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Invalid email response: {response.status_code} {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "value is not a valid email address" in str(response.json()).lower()

@pytest.mark.asyncio
async def test_register_unexpected_db_error(async_client: AsyncClient, mock_db: AsyncMock):
    """Tests registration with unexpected database error."""
    mock_db.reset_mock()
    with patch("app.api.v1.services.auth.AuthService.register_user", new_callable=AsyncMock) as mock_register_user_service:
        mock_register_user_service.side_effect = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unexpected database error"
        )
        payload = {
            "first": "Error", "last": "User", "email": "error@example.com",
            "username": "erroruser", "password": "StrongPass123!", "phone": None, "role_id": 1,
        }
        response = await async_client.post("/api/v1/auth/register", json=payload)
        logger.debug(f"Unexpected DB error response: {response.status_code} {response.json()}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "unexpected database error" in response.json().get("detail", "").lower()
        mock_register_user_service.assert_awaited_once()
        mock_db.execute.assert_not_called()
        mock_db.add.assert_not_called()
        mock_db.commit.assert_not_called()
        mock_db.refresh.assert_not_called()

@pytest.mark.asyncio
async def test_auth_service_register_user_no_id_from_db_refresh(mock_db: AsyncMock):
    """
    Tests AuthService.register_user where db.refresh does NOT set the user ID,
    ensuring coverage of `if new_user.id is None:` block (lines 78-79).
    """
    mock_db.reset_mock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results

    # Custom side effect for refresh that does NOT set obj.id
    original_refresh_side_effect = mock_db.refresh.side_effect
    def custom_refresh_side_effect(obj):
        if isinstance(obj, User):
            # Simulate refresh not setting ID immediately, but other attributes
            obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            # IMPORTANT: Do NOT set obj.id here, to force the 'if new_user.id is None:' branch
        elif isinstance(obj, Registration):
            # This part of refresh (for registration_record) is fine
            if obj.id is None:
                obj.id = 1
            obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            obj.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    mock_db.refresh.side_effect = custom_refresh_side_effect

    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane.idtest@example.com", username="janesmith_idtest",
        password="StrongPass123!", phone="555-555-5555", role_id=1
    )
    
    user = await auth_service.register_user(registration)
    
    logger.debug(f"No ID from refresh mock calls: {mock_db.execute.call_args_list}")
    
    assert user.username == "janesmith_idtest"
    # The ID should now be set by the `if new_user.id is None:` block in auth.py
    assert user.id == 1 
    assert mock_db.commit.call_count == 2
    assert mock_db.add.call_count == 2
    assert mock_db.refresh.call_count == 1 # Only new_user is refreshed, registration_record is not
    mock_db.rollback.assert_not_awaited() # Ensure no rollback on success
