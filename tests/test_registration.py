import pytest
from fastapi import status, HTTPException, Depends
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock
from app.main import app
# Import the actual get_current_user from the dependencies module
from app.api.v1.dependencies import get_current_user as main_get_current_user
from app.api.v1.dependencies.permissions import require_permission
from app.core.db.session import get_db
from app.api.v1.models.registration import Registration as RegistrationModel
from app.api.v1.services.registration import RegistrationService
from app.api.v1.schemas.registration import RegistrationCreate, RegistrationUpdate, Registration
from app.api.v1.validators.registration import ensure_unique_registration_email, ensure_unique_registration_username
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError 
import logging

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dummy current user and role (reused from test_user.py)
class DummyUser:
    id = 1
    username = "admin"
    role_id = 1

class DummyRole:
    id = 1
    name = "admin"
    permissions = ["create", "read", "update", "delete"]

# Async dummy current user (reused from test_user.py)
async def dummy_get_current_user():
    logger.debug("Dummy get_current_user called")
    return DummyUser()

# Async dummy permission checker (reused from test_user.py)
def dummy_require_permission(permission: str):
    logger.debug(f"Dummy require permission called for: {permission}")
    async def inner(user: DummyUser = Depends(dummy_get_current_user), db: AsyncSession = Depends(get_db)):
        # In a real scenario, you'd check user's role and permissions against 'permission' argument
        # For testing purposes, we assume the dummy user always has the required permission.
        logger.debug(f"Dummy permission check for: {permission} - returning user {user.username}")
        return user
    return inner

# DB fixture with awaited async mocks (aligned with test_user.py and test_dependencies.py)
@pytest.fixture
async def async_client():
    # Override the main get_current_user dependency directly to bypass all authentication logic
    app.dependency_overrides[main_get_current_user] = dummy_get_current_user
    app.dependency_overrides[require_permission] = dummy_require_permission
    
    # Create an AsyncMock for DB session
    db = AsyncMock(spec=AsyncSession) # Use spec=AsyncSession for better type checking
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    # IMPORTANT: Use MagicMock for db.add to prevent RuntimeWarning, as it's not awaited in service code.
    db.add = MagicMock() 
    
    # Mock db.execute to return a MagicMock with proper scalars support, aligned with test_user.py
    mock_result_instance = MagicMock()
    mock_scalars_result_instance = MagicMock()
    mock_scalars_result_instance.first.return_value = DummyRole() # For Role lookups if needed
    mock_scalars_result_instance.all.return_value = [] # Default for all()
    mock_result_instance.scalars.return_value = mock_scalars_result_instance
    mock_result_instance.scalar_one_or_none.return_value = DummyRole() # Default for scalar_one_or_none()
    db.execute.return_value = mock_result_instance

    async def mock_get_db():
        logger.debug("Mock get_db called")
        yield db

    app.dependency_overrides[get_db] = mock_get_db

    # Setup HTTPX client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Clear overrides after the test
    app.dependency_overrides.clear()


# Registration model factory (NO updated_at, consistent with provided model)
def registration_model_stub(**kwargs):
    # Ensure timezone-naive datetime objects for consistency with DB models
    return RegistrationModel(
        id=kwargs.get("id", 1),
        first=kwargs.get("first", "Test"),
        last=kwargs.get("last", "User"),
        username=kwargs.get("username", "testuser"),
        email=kwargs.get("email", "test@example.com"),
        password=kwargs.get("password", "hashed_password"),
        phone=kwargs.get("phone", None),
        role_id=kwargs.get("role_id", 1),
        created_at=kwargs.get("created_at", datetime.now(timezone.utc).replace(tzinfo=None))
    )

# --- Service-level tests for app/api/v1/services/registration.py ---

@pytest.mark.asyncio
async def test_service_get_all_registrations():
    """Test RegistrationService.get_all_registrations."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    expected_registrations = [
        registration_model_stub(id=1, username="reg1"),
        registration_model_stub(id=2, username="reg2"),
    ]
    # Ensure .all() returns a list of RegistrationModel instances
    mock_scalar_result.all.return_value = expected_registrations
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    registrations = await RegistrationService.get_all_registrations(db)
    assert len(registrations) == 2
    assert registrations[0].username == "reg1"
    assert registrations[1].username == "reg2"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_all_registrations_empty():
    """Test RegistrationService.get_all_registrations when no registrations exist."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_scalar_result = MagicMock()
    mock_scalar_result.all.return_value = []
    mock_result.scalars.return_value = mock_scalar_result
    db.execute.return_value = mock_result

    registrations = await RegistrationService.get_all_registrations(db)
    assert len(registrations) == 0
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_registration():
    """Test RegistrationService.get_registration."""
    db = AsyncMock()
    mock_result = MagicMock()
    expected_registration = registration_model_stub(id=1, username="testreg")
    # Ensure .scalar_one_or_none() returns a single RegistrationModel instance
    mock_result.scalar_one_or_none.return_value = expected_registration
    db.execute.return_value = mock_result

    registration = await RegistrationService.get_registration(1, db)
    assert registration.id == 1
    assert registration.username == "testreg"
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_get_registration_not_found():
    """Test RegistrationService.get_registration when registration is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    registration = await RegistrationService.get_registration(999, db)
    assert registration is None
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_registration():
    """Test RegistrationService.create_registration."""
    db = AsyncMock()
    # Explicitly mock db.add as MagicMock within the test to avoid the RuntimeWarning
    db.add = MagicMock() 
    registration_in = RegistrationCreate(
        first="New", last="Reg", username="newreg", email="new@example.com",
        password="SecurePass123!", phone=None, role_id=1
    )
    
    # Mock db.refresh to simulate DB assigning ID and created_at
    def refresh_side_effect(obj):
        obj.id = 1
        obj.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.refresh.side_effect = refresh_side_effect

    registration = await RegistrationService.create_registration(registration_in, db)
    assert registration.username == "newreg"
    assert registration.email == "new@example.com"
    db.add.assert_called_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_create_registration_db_commit_failure():
    """Test UserService.create_user with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    db.add = MagicMock() # Explicitly mock db.add
    user_in = RegistrationCreate( # Renamed from user_in to registration_in for consistency
        email="failcommit@example.com", username="failcommit",
        password="SecurePass123!", role_id=2, first="Commit", last="Fail"
    )
    db.commit.side_effect = SQLAlchemyError("Simulated commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated commit error"):
        await RegistrationService.create_registration(user_in, db) # Changed to user_in for test consistency
    
    db.add.assert_called_once() # User is added before commit attempt
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited() # Refresh should not be called if commit fails

@pytest.mark.asyncio
async def test_service_create_registration_db_refresh_failure():
    """Test UserService.create_user with db.refresh raising SQLAlchemyError."""
    db = AsyncMock()
    db.add = MagicMock() # Explicitly mock db.add
    user_in = RegistrationCreate( # Renamed from user_in to registration_in for consistency
        email="failrefresh@example.com", username="failrefresh",
        password="SecurePass123!", role_id=2, first="Refresh", last="Fail"
    )
    # Ensure commit succeeds, then refresh fails
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await RegistrationService.create_registration(user_in, db) # Changed to user_in for test consistency
    
    db.add.assert_called_once()
    db.commit.assert_awaited_once() # Commit should have been called before refresh
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_registration():
    """Test RegistrationService.update_registration."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1, username="old_reg", email="old@example.com")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result # For the get_registration call inside update

    # Provide all fields for RegistrationUpdate to avoid Pydantic ValidationError
    # Mimics sending a complete payload, even for optional fields
    registration_in = RegistrationUpdate(
        first=existing_registration.first,
        last=existing_registration.last,
        username="updated_reg", # This is the field being updated
        email="updated@example.com", # This is the field being updated
        password=existing_registration.password, # Must provide even if not changing
        phone=existing_registration.phone, # Can be None
        role_id=existing_registration.role_id # Must provide
    )
    
    # Mock db.refresh to simulate DB refresh updating attributes
    def refresh_side_effect(obj):
        obj.username = "updated_reg" # Simulate attribute update on refresh
        obj.email = "updated@example.com"
        # No updated_at in the Registration model, so don't set it here.
    db.refresh.side_effect = refresh_side_effect

    updated_registration = await RegistrationService.update_registration(1, registration_in, db)

    assert updated_registration.username == "updated_reg"
    assert updated_registration.email == "updated@example.com"
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_update_registration_not_found():
    """Test RegistrationService.update_registration when registration is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    # Provide all fields to avoid Pydantic ValidationError
    registration_in = RegistrationUpdate(
        first="Dummy", last="Data", username="nonexistent_update",
        email="dummy@example.com", password="DummyPassword1!", phone=None, role_id=1
    )
    updated_registration = await RegistrationService.update_registration(999, registration_in, db)
    assert updated_registration is None
    db.execute.assert_awaited_once()
    db.commit.assert_not_awaited()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_registration_db_commit_failure():
    """Test RegistrationService.update_registration with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1, username="old_reg")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result

    # Provide all fields to avoid Pydantic ValidationError
    registration_in = RegistrationUpdate(
        first=existing_registration.first,
        last=existing_registration.last,
        username="fail_commit",
        email=existing_registration.email,
        password=existing_registration.password,
        phone=existing_registration.phone,
        role_id=existing_registration.role_id
    )
    db.commit.side_effect = SQLAlchemyError("Simulated update commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated update commit error"):
        await RegistrationService.update_registration(1, registration_in, db)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_update_registration_db_refresh_failure():
    """Test RegistrationService.update_registration with db.refresh raising SQLAlchemyError."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1, username="old_reg")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result

    # Provide all fields to avoid Pydantic ValidationError
    registration_in = RegistrationUpdate(
        first=existing_registration.first,
        last=existing_registration.last,
        username="fail_refresh",
        email=existing_registration.email,
        password=existing_registration.password,
        phone=existing_registration.phone,
        role_id=existing_registration.role_id
    )
    db.refresh.side_effect = SQLAlchemyError("Simulated refresh error")

    with pytest.raises(SQLAlchemyError, match="Simulated refresh error"):
        await RegistrationService.update_registration(1, registration_in, db)
    
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_registration():
    """Test RegistrationService.delete_registration."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result

    deleted = await RegistrationService.delete_registration(1, db)
    assert deleted is True
    db.execute.assert_awaited_once()
    db.delete.assert_called_once_with(existing_registration)
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_service_delete_registration_not_found():
    """Test RegistrationService.delete_registration when registration is not found."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    deleted = await RegistrationService.delete_registration(999, db)
    assert deleted is False
    db.execute.assert_awaited_once()
    db.delete.assert_not_called()
    db.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_registration_db_delete_failure():
    """Test RegistrationService.delete_registration with db.delete raising SQLAlchemyError."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result

    db.delete.side_effect = SQLAlchemyError("Simulated delete error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete error"):
        await RegistrationService.delete_registration(1, db)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_not_awaited()

@pytest.mark.asyncio
async def test_service_delete_registration_db_commit_failure():
    """Test RegistrationService.delete_registration with db.commit raising SQLAlchemyError."""
    db = AsyncMock()
    existing_registration = registration_model_stub(id=1)
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_registration
    db.execute.return_value = mock_result

    db.commit.side_effect = SQLAlchemyError("Simulated delete commit error")

    with pytest.raises(SQLAlchemyError, match="Simulated delete commit error"):
        await RegistrationService.delete_registration(1, db)
    
    db.execute.assert_awaited_once()
    db.delete.assert_called_once()
    db.commit.assert_awaited_once()


# --- Validator-level tests for app/api/v1/validators/registration.py ---

@pytest.mark.asyncio
async def test_validator_ensure_unique_registration_email_exists():
    """Test ensure_unique_registration_email when email already exists."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = registration_model_stub(email="existing@example.com")
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await ensure_unique_registration_email("existing@example.com", db)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Email already used for registration."
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_validator_ensure_unique_registration_email_not_exists():
    """Test ensure_unique_registration_email when email does not exist."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    # No exception should be raised
    await ensure_unique_registration_email("new@example.com", db)
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_validator_ensure_unique_registration_username_exists():
    """Test ensure_unique_registration_username when username already exists."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = registration_model_stub(username="existinguser")
    db.execute.return_value = mock_result

    with pytest.raises(HTTPException) as exc_info:
        await ensure_unique_registration_username("existinguser", db)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Username already used for registration."
    db.execute.assert_awaited_once()

@pytest.mark.asyncio
async def test_validator_ensure_unique_registration_username_not_exists():
    """Test ensure_unique_registration_username when username does not exist."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    db.execute.return_value = mock_result

    # No exception should be raised
    await ensure_unique_registration_username("newuser", db)
    db.execute.assert_awaited_once()


# --- Route-level tests for app/api/v1/routes/registration.py ---

@pytest.mark.asyncio
async def test_route_read_registrations(async_client, monkeypatch):
    async def mock_get_all_registrations(db):
        logger.debug("Mock get_all_registrations called")
        # Return Pydantic Registration schema instances as expected by the route
        return [
            Registration.from_orm(registration_model_stub(id=1, username="reg1")),
            Registration.from_orm(registration_model_stub(id=2, username="reg2")),
        ]

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.get_all_registrations", mock_get_all_registrations)

    logger.debug("Sending GET request to /api/v1/registrations/")
    response = await async_client.get(
        "/api/v1/registrations/",
        headers={"Authorization": "Bearer fake-token"} # This token is now purely for headers, not for validation
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["username"] == "reg1"
    assert data[1]["username"] == "reg2"

@pytest.mark.asyncio
async def test_route_read_registration(async_client, monkeypatch):
    async def mock_get_registration(registration_id, db):
        logger.debug("Mock get_registration called")
        # Return Pydantic Registration schema instance as expected by the route
        return Registration.from_orm(registration_model_stub(id=registration_id, username="single_reg"))

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.get_registration", mock_get_registration)

    logger.debug("Sending GET request to /api/v1/registrations/1")
    response = await async_client.get(
        "/api/v1/registrations/1",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "single_reg"

@pytest.mark.asyncio
async def test_route_read_registration_not_found(async_client, monkeypatch):
    """Test read_registration route when registration is not found (covers line 27 in route)."""
    async def mock_get_registration(registration_id, db):
        logger.debug("Mock get_registration called (returns None)")
        return None

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.get_registration", mock_get_registration)

    logger.debug("Sending GET request to /api/v1/registrations/999 (nonexistent)")
    response = await async_client.get(
        "/api/v1/registrations/999",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Registration not found"

@pytest.mark.asyncio
async def test_route_create_registration(async_client, monkeypatch):
    async def mock_create_registration(registration_in, db):
        logger.debug("Mock create_registration called")
        # Return a Pydantic Registration schema instance
        return Registration.from_orm(registration_model_stub(
            id=1, # Assign a dummy ID as it would be created
            first=registration_in.first,
            last=registration_in.last,
            username=registration_in.username,
            email=registration_in.email,
            role_id=registration_in.role_id,
            phone=registration_in.phone, # Include phone for completeness
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        ))

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.create_registration", mock_create_registration)

    payload = {
        "first": "Route", "last": "Create", "username": "routecreate", "email": "rc@example.com",
        "password": "SecurePass123!", "phone": None, "role_id": 1
    }
    logger.debug("Sending POST request to /api/v1/registrations/")
    response = await async_client.post(
        "/api/v1/registrations/",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["username"] == "routecreate"
    assert data["email"] == "rc@example.com"
    assert "id" in data # Ensure ID is present

@pytest.mark.asyncio
async def test_route_update_registration(async_client, monkeypatch):
    async def mock_update_registration(registration_id, registration_in, db):
        logger.debug("Mock update_registration called")
        # Return a Pydantic Registration schema instance, reflecting updates
        original_stub = registration_model_stub(id=registration_id)
        return Registration.from_orm(registration_model_stub(
            id=registration_id,
            first=registration_in.first if registration_in.first else original_stub.first,
            last=registration_in.last if registration_in.last else original_stub.last,
            username=registration_in.username if registration_in.username else original_stub.username,
            email=registration_in.email if registration_in.email else original_stub.email,
            password=registration_in.password if registration_in.password else original_stub.password,
            phone=registration_in.phone if registration_in.phone else original_stub.phone,
            role_id=registration_in.role_id if registration_in.role_id else original_stub.role_id,
            created_at=original_stub.created_at # Keep original created_at
        ))

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.update_registration", mock_update_registration)

    # Payload for update must contain all fields as per RegistrationUpdate schema's requirements
    # since it lacks `= None` defaults.
    payload = {
        "first": "UpdatedRoute",
        "last": "Reg",
        "username": "updated_route_reg",
        "email": "updated_route@example.com",
        "password": "NewSecurePass123!", # Even if not changing, must be present
        "phone": "987-654-3210",
        "role_id": 2
    }
    logger.debug("Sending PUT request to /api/v1/registrations/1")
    response = await async_client.put(
        "/api/v1/registrations/1",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "updated_route_reg"
    assert data["email"] == "updated_route@example.com"

@pytest.mark.asyncio
async def test_route_update_registration_not_found(async_client, monkeypatch):
    """Test update_registration route when registration is not found (covers line 54 in route)."""
    async def mock_update_registration(registration_id, registration_in, db):
        logger.debug("Mock update_registration called (returns None)")
        return None

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.update_registration", mock_update_registration)

    # Payload for update must contain all fields as per RegistrationUpdate schema's requirements
    payload = {
        "first": "NonExistent", "last": "User", "username": "nonexistent_update",
        "email": "nonexistent@example.com", "password": "Password123!", "phone": None, "role_id": 1
    }
    logger.debug("Sending PUT request to /api/v1/registrations/999 (nonexistent)")
    response = await async_client.put(
        "/api/v1/registrations/999",
        json=payload,
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Registration not found"

@pytest.mark.asyncio
async def test_route_delete_registration(async_client, monkeypatch):
    async def mock_delete_registration(registration_id, db):
        logger.debug("Mock delete_registration called")
        return True

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.delete_registration", mock_delete_registration)

    logger.debug("Sending DELETE request to /api/v1/registrations/1")
    response = await async_client.delete(
        "/api/v1/registrations/1",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.text}")
    assert response.status_code == status.HTTP_204_NO_CONTENT

@pytest.mark.asyncio
async def test_route_delete_registration_not_found(async_client, monkeypatch):
    """Test delete_registration route when registration is not found (covers line 65 in route)."""
    async def mock_delete_registration(registration_id, db):
        logger.debug("Mock delete_registration called (returns False)")
        return False

    monkeypatch.setattr("app.api.v1.services.registration.RegistrationService.delete_registration", mock_delete_registration)

    logger.debug("Sending DELETE request to /api/v1/registrations/999 (nonexistent)")
    response = await async_client.delete(
        "/api/v1/registrations/999",
        headers={"Authorization": "Bearer fake-token"}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Registration not found"
