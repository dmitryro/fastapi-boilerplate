import pytest
from fastapi import status, HTTPException
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.api.v1.models.user import User
from app.api.v1.models.role import Role
from app.api.v1.models.registration import Registration
from app.api.v1.services.auth import AuthService
from app.api.v1.schemas.registration import RegistrationSchema
from datetime import datetime, timezone
from argon2 import PasswordHasher
import logging

logger = logging.getLogger(__name__)
pwd_context = PasswordHasher()

def mock_result(scalar):
    result = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.first.return_value = scalar
    result.scalars.return_value = scalars_mock
    result.scalar_one_or_none.return_value = scalar
    return result

@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient, mock_db):
    """Tests successful user registration via the /register endpoint."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    mock_db.add = AsyncMock()
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
    assert mock_db.commit.call_count >= 1
    assert response.json()["username"] == "janesmith"

@pytest.mark.asyncio
async def test_register_existing_username(async_client: AsyncClient, mock_db):
    """Tests registration failure when username exists in User."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(User(id=1, username="existingusername", email="existing@example.com",
                         password=pwd_context.hash("Password123!"),
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
async def test_register_existing_email(async_client: AsyncClient, mock_db):
    """Tests registration failure when email exists in User."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None),
        mock_result(User(id=2, username="otheruser", email="duplicate@example.com",
                         password=pwd_context.hash("Password123!"),
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
async def test_register_existing_registration_username(async_client: AsyncClient, mock_db):
    """Tests registration failure when username exists in Registration."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(Registration(id=1, username="existingusername", email="existing@example.com",
                                 password=pwd_context.hash("Password123!")))
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
async def test_register_existing_registration_email(async_client: AsyncClient, mock_db):
    """Tests registration failure when email exists in Registration."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(Registration(id=2, username="otheruser", email="duplicate@example.com",
                                 password=pwd_context.hash("Password123!")))
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
async def test_register_invalid_password(async_client: AsyncClient, mock_db):
    """Tests registration with short password, expecting validation error."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
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

@pytest.mark.asyncio
async def test_register_invalid_role_id_route(async_client: AsyncClient, mock_db):
    """Tests registration failure when role_id does not exist."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
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
async def test_login_invalid_password_length_route(async_client: AsyncClient, mock_db):
    """Tests login with short password."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None)
    ]
    mock_db.execute.side_effect = query_results
    response = await async_client.post("/api/v1/auth/login", data={
        "username": "testuser",
        "password": "short"
    })
    logger.debug(f"Login invalid password response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect username or password" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_login_malformed_headers_route(async_client: AsyncClient, mock_db):
    """Tests login with malformed Authorization header."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(User(id=1, username="testuser", password=pwd_context.hash("password123"),
                         created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                         updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    ]
    mock_db.execute.side_effect = query_results
    response = await async_client.post("/api/v1/auth/login", headers={"Authorization": "Invalid"},
                                      data={"username": "testuser", "password": "password123"})
    logger.debug(f"Login malformed headers response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient, mock_db):
    """Tests successful login."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    test_password = "password123"
    hashed_password = pwd_context.hash(test_password)
    dummy_user = User(
        id=1, username="testuser", password=hashed_password, role_id=1,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    query_results = [
        mock_result(dummy_user),
    ]
    mock_db.execute.side_effect = query_results
    response = await async_client.post("/api/v1/auth/login", data={
        "username": "testuser",
        "password": "password123"
    })
    logger.debug(f"Login success response: {response.status_code} {response.json()}")
    logger.debug(f"Mock execute calls: {mock_db.execute.call_args_list}")
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_auth_service_authenticate_success(mock_db):
    """Tests AuthService.authenticate_user success."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    test_password = "testpass123"
    hashed_password = pwd_context.hash(test_password)
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

@pytest.mark.asyncio
async def test_auth_service_authenticate_wrong_password(mock_db):
    """Tests AuthService.authenticate_user with wrong password."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    correct_password = "correctpass123"
    hashed_password = pwd_context.hash(correct_password)
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
async def test_auth_service_authenticate_nonexistent_user(mock_db):
    """Tests AuthService.authenticate_user for nonexistent user."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None)
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    user = await auth_service.authenticate_user("nonexistent", "any_password123")
    logger.debug(f"Authenticate nonexistent user mock calls: {mock_db.execute.call_args_list}")
    assert user is None

@pytest.mark.asyncio
async def test_auth_service_register_user_success(mock_db):
    """Tests AuthService.register_user success."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    mock_db.add = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    user = await auth_service.register_user(registration)
    logger.debug(f"Register user success mock calls: {mock_db.execute.call_args_list}")
    assert user.username == "janesmith"
    assert mock_db.commit.call_count >= 1

@pytest.mark.asyncio
async def test_auth_service_register_user_duplicate_user_username(mock_db):
    """Tests AuthService.register_user with duplicate user username."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(User(id=1, username="janesmith", email="existing@example.com",
                         password=pwd_context.hash("Password123!"),
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

@pytest.mark.asyncio
async def test_auth_service_register_user_duplicate_user_email(mock_db):
    """Tests AuthService.register_user with duplicate user email."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None),
        mock_result(User(id=2, username="otheruser", email="jane@example.com",
                         password=pwd_context.hash("Password123!"),
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

@pytest.mark.asyncio
async def test_auth_service_register_user_invalid_role(mock_db):
    """Tests AuthService.register_user with invalid role_id."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(None),  # Role check
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

@pytest.mark.asyncio
async def test_auth_service_register_user_db_failure(mock_db):
    """Tests AuthService.register_user with database failure."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    mock_db.add = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    mock_db.commit.side_effect = Exception("Database commit failed")
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="Jane", last="Smith", email="jane@example.com", username="janesmith",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    with pytest.raises(Exception) as exc_info:
        await auth_service.register_user(registration)
    logger.debug(f"DB failure mock calls: {mock_db.execute.call_args_list}")
    assert "database commit failed" in str(exc_info.value).lower()

@pytest.mark.asyncio
async def test_register_empty_payload(async_client: AsyncClient, mock_db):
    """Tests registration with empty payload."""
    mock_db.reset_mock()
    response = await async_client.post("/api/v1/auth/register", json={})
    logger.debug(f"Empty payload response: {response.status_code} {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "field required" in str(response.json()).lower()

@pytest.mark.asyncio
async def test_register_invalid_email_format(async_client: AsyncClient, mock_db):
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
async def test_register_unexpected_db_error(async_client: AsyncClient, mock_db):
    """Tests registration with unexpected database error."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    mock_db.add = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    mock_db.add.side_effect = Exception("Unexpected database error")
    payload = {
        "first": "Error", "last": "User", "email": "error@example.com",
        "username": "erroruser", "password": "StrongPass123!", "phone": None, "role_id": 1,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Unexpected DB error response: {response.status_code} {response.json()}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "unexpected database error" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_user_no_id_assigned(mock_db):
    """Tests AuthService.register_user when no ID is assigned to the user."""
    mock_db.reset_mock()
    mock_db.execute = AsyncMock()
    mock_db.add = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()
    query_results = [
        mock_result(None),  # User username check
        mock_result(None),  # User email check
        mock_result(None),  # Registration username check
        mock_result(None),  # Registration email check
        mock_result(Role(id=1, name="user")),  # Role check
    ]
    mock_db.execute.side_effect = query_results
    # Simulate no ID assignment after commit
    async def mock_refresh(user):
        user.id = None  # Ensure id remains None after refresh
    mock_db.refresh.side_effect = mock_refresh
    auth_service = AuthService(db=mock_db)
    registration = RegistrationSchema(
        first="NoID", last="User", email="noid@example.com", username="noiduser",
        password="StrongPass123!", phone="555-1234", role_id=1
    )
    user = await auth_service.register_user(registration)
    logger.debug(f"No ID assigned mock calls: {mock_db.execute.call_args_list}")
    assert user.id == 1  # Verify fallback ID assignment
    assert mock_db.commit.call_count >= 2
    assert user.username == "noiduser"
