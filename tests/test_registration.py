import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.core.db.session import AsyncSessionLocal
from fastapi import status

@pytest.fixture(scope="module")
async def async_client():
    transport = ASGITransport(app=app, lifespan="on")
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

@pytest.fixture
async def async_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session

@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    payload = {
        "email": "newregister@example.com",
        "username": "newregister",
        "password": "registerpass",
        "role_id": 2
    }
    response = await async_client.post("/api/v1/registration", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == payload["email"]
    assert "id" in data

@pytest.mark.asyncio
async def test_register_existing_email(async_client: AsyncClient, async_session: AsyncSession):
    # Create user with the email first
    from app.api.v1.models.user import User
    from app.api.v1.security.passwords import hash_password

    user = User(
        email="existingemail@example.com",
        username="userexists",
        password=hash_password("password"),
        role_id=2
    )
    async_session.add(user)
    await async_session.commit()

    payload = {
        "email": "existingemail@example.com",
        "username": "anotheruser",
        "password": "anotherpass",
        "role_id": 2
    }
    response = await async_client.post("/api/v1/registration", json=payload)
    assert response.status_code == 400
    assert "email" in response.json()["detail"].lower()

@pytest.mark.asyncio
async def test_register_existing_username(async_client: AsyncClient, async_session: AsyncSession):
    # Create user with the username first
    from app.api.v1.models.user import User
    from app.api.v1.security.passwords import hash_password

    user = User(
        email="uniqueemail@example.com",
        username="existingusername",
        password=hash_password("password"),
        role_id=2
    )
    async_session.add(user)
    await async_session.commit()

    payload = {
        "email": "newemail@example.com",
        "username": "existingusername",
        "password": "newpass",
        "role_id": 2
    }
    response = await async_client.post("/api/v1/registration", json=payload)
    assert response.status_code == 400
    assert "username" in response.json()["detail"].lower()

