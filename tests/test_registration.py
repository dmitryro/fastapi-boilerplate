import pytest
from fastapi import status, HTTPException
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock
from app.main import app
from app.api.v1.security.jwt import get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
import logging
from datetime import datetime

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class DummyUser:
    id = 1
    username = "testuser"
    role_id = 1  # admin role

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

async def dummy_guard(*args, **kwargs):
    logger.debug("Dummy guard called")
    return DummyUser()

def dummy_require_permission(permission: str):
    logger.debug(f"Require permission called for: {permission}")
    return dummy_guard

@pytest.fixture
async def async_client():
    # Override FastAPI dependencies globally
    app.dependency_overrides[get_current_user] = dummy_guard
    app.dependency_overrides[require_permission] = dummy_require_permission

    # Mock database session
    async def mock_get_db():
        db = AsyncMock()
        db.execute = AsyncMock(return_value=type('Result', (), {
            'scalar_one_or_none': lambda: DummyRole(),
            'scalars': lambda: type('Scalars', (), {'first': lambda: DummyUser()})()
        })())
        yield db
    app.dependency_overrides[get_db] = mock_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    # Clean up overrides after fixture
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_register_success(async_client, monkeypatch):
    async def mock_create_registration(registration_in, db):
        logger.debug("Mock create_registration called")
        return {
            "id": 1,
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",  # Include password
            "role_id": 2,
            "first": "Test",
            "last": "User",
            "phone": None,
            "created_at": datetime.now().isoformat(),  # Include created_at
        }
    monkeypatch.setattr(
        "app.api.v1.services.registration.RegistrationService.create_registration",
        mock_create_registration
    )

    logger.debug("Sending POST request to /api/v1/registrations/")
    response = await async_client.post(
        "/api/v1/registrations/",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "role_id": 2,
            "first": "Test",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}  # Keep query parameters
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["email"] == "test@example.com"

@pytest.mark.asyncio
async def test_register_existing_email(async_client, monkeypatch):
    async def raise_http_exc(*args, **kwargs):
        logger.debug("Mock raise_http_exc called")
        raise HTTPException(status_code=400, detail="Email already registered")
    monkeypatch.setattr(
        "app.api.v1.services.registration.RegistrationService.create_registration",
        raise_http_exc
    )

    response = await async_client.post(
        "/api/v1/registrations/",
        json={
            "email": "existing@example.com",
            "username": "newuser",
            "password": "SecurePass123!",
            "role_id": 2,
            "first": "Existing",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}  # Keep query parameters
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Email already registered"

@pytest.mark.asyncio
async def test_register_existing_username(async_client, monkeypatch):
    async def raise_http_exc(*args, **kwargs):
        logger.debug("Mock raise_http_exc called")
        raise HTTPException(status_code=400, detail="Username already registered")
    monkeypatch.setattr(
        "app.api.v1.services.registration.RegistrationService.create_registration",
        raise_http_exc
    )

    response = await async_client.post(
        "/api/v1/registrations/",
        json={
            "email": "newemail@example.com",
            "username": "existinguser",
            "password": "SecurePass123!",
            "role_id": 2,
            "first": "Existing",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}  # Keep query parameters
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Username already registered"

@pytest.mark.asyncio
async def test_register_invalid_password(async_client, monkeypatch):
    response = await async_client.post(
        "/api/v1/registrations/",
        json={
            "email": "invalid@example.com",
            "username": "invaliduser",
            "password": "short",
            "role_id": 2,
            "first": "Invalid",
            "last": "User",
            "phone": None,
        },
        headers={"Authorization": "Bearer fake-token"},
        params={"args": "", "kwargs": ""}  # Keep query parameters
    )
    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    errors = response.json().get("detail", [])
    assert any("password" in str(err.get("loc")) for err in errors)

@pytest.mark.parametrize("field,value", [
    ("email", ""),
    ("username", ""),
    ("password", "short"),
])
async def test_register_invalid_field(field, value, async_client):
    payload = {
        "email": "user@example.com",
        "username": "validuser",
        "password": "SecurePass123!",
        "role_id": 2,
        "first": "Valid",
        "last": "User",
        "phone": None,
    }
    payload[field] = value
    response = await async_client.post("/api/v1/registrations/", json=payload)
    assert response.status_code == 422

