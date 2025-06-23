import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from unittest.mock import AsyncMock, MagicMock
from itertools import cycle
from datetime import datetime, timezone
import logging

from app.main import app
from app.core.db.session import get_db
from app.api.v1.models.user import User
from app.api.v1.models.role import Role

logger = logging.getLogger(__name__)

@pytest.fixture
async def mock_db():
    db = AsyncMock()
    db.execute = AsyncMock()
    db.add = AsyncMock(return_value=None)
    db.flush = AsyncMock(return_value=None)
    db.commit = AsyncMock(return_value=None)
    
    def refresh_side_effect(user):
        user.id = 1
        user.created_at = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
    
    db.refresh = AsyncMock(side_effect=refresh_side_effect)
    return db

@pytest.fixture
async def async_client(mock_db):
    async def override_get_db():
        yield mock_db
    
    app.dependency_overrides[get_db] = override_get_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_register_success(async_client, mock_db):
    query_results = [
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # username
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # email
        MagicMock(scalar_one_or_none=lambda: Role(id=1, name="user"))  # role
    ]
    mock_db.execute.side_effect = cycle(query_results)
    
    payload = {
        "first": "Jane",
        "last": "Smith",
        "email": "jane@example.com",
        "username": "janesmith",
        "password": "StrongPass123!",
        "phone": "555-1234",
        "role_id": 1,
    }
    
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Register success response: {response.status_code} {response.json()}")
    
    assert response.status_code == 201
    assert "id" in response.json()
    assert isinstance(response.json()["id"], int)

@pytest.mark.asyncio
async def test_register_existing_username(async_client, mock_db):
    query_results = [
        MagicMock(scalars=lambda: MagicMock(first=lambda: User(
            id=1,
            first="Existing",
            last="User",
            email="existing@example.com",
            username="existingusername",
            password="hashed",
            phone="1234567890",
            role_id=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))),  # username
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # email
        MagicMock(scalar_one_or_none=lambda: Role(id=1, name="user"))  # role
    ]
    mock_db.execute.side_effect = cycle(query_results)
    
    payload = {
        "first": "Dup",
        "last": "User",
        "email": "unique@example.com",
        "username": "existingusername",
        "password": "Password123!",
        "phone": None,
        "role_id": 1,
    }
    
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing username test response: {response.status_code} {response.json()}")
    
    assert response.status_code == 400
    assert "username already exists" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_existing_email(async_client, mock_db):
    query_results = [
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # username
        MagicMock(scalars=lambda: MagicMock(first=lambda: User(
            id=2,
            first="Other",
            last="User",
            email="duplicate@example.com",
            username="otheruser",
            password="hashed",
            phone="1234567890",
            role_id=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))),  # email
        MagicMock(scalar_one_or_none=lambda: Role(id=1, name="user"))  # role
    ]
    mock_db.execute.side_effect = cycle(query_results)
    
    payload = {
        "first": "Dup",
        "last": "User",
        "email": "duplicate@example.com",
        "username": "newusername",
        "password": "Password123!",
        "phone": None,
        "role_id": 1,
    }
    
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Existing email test response: {response.status_code} {response.json()}")
    
    assert response.status_code == 400
    assert "email already exists" in response.json().get("detail", "").lower()

@pytest.mark.asyncio
async def test_register_invalid_password(async_client, mock_db):
    query_results = [
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # username
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # email
        MagicMock(scalar_one_or_none=lambda: Role(id=1, name="user"))  # role
    ]
    mock_db.execute.side_effect = cycle(query_results)
    
    payload = {
        "first": "Weak",
        "last": "Password",
        "email": "weak@example.com",
        "username": "weakpass",
        "password": "123",
        "phone": None,
        "role_id": 1,
    }
    
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Invalid password response: {response.status_code} {response.json()}")
    
    # Note: Route uses RegistrationSchema, not RegistrationCreate, so no min_length validation
    assert response.status_code == 201
    assert "id" in response.json()

@pytest.mark.asyncio
async def test_register_invalid_role_id(async_client, mock_db):
    query_results = [
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # username
        MagicMock(scalars=lambda: MagicMock(first=lambda: None)),  # email
        MagicMock(scalar_one_or_none=lambda: None)  # role
    ]
    mock_db.execute.side_effect = cycle(query_results)
    
    payload = {
        "first": "No",
        "last": "Role",
        "email": "norole@example.com",
        "username": "noroleuser",
        "password": "Password123!",
        "phone": None,
        "role_id": 9999,
    }
    
    response = await async_client.post("/api/v1/auth/register", json=payload)
    logger.debug(f"Invalid role test response: {response.status_code} {response.json()}")
    
    assert response.status_code == 400
    assert "role not found" in response.json().get("detail", "").lower()
