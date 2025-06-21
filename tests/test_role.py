import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.core.db.session import AsyncSessionLocal
from app.api.v1.models.role import Role

@pytest.fixture(scope="module")
async def async_client():
    transport = ASGITransport(app=app, lifespan="on")
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

@pytest.fixture
async def async_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session

@pytest.fixture
async def create_test_role(async_session: AsyncSession):
    q = await async_session.execute(
        Role.__table__.select().where(Role.name == "member")
    )
    role = q.scalar_one_or_none()
    if not role:
        role = Role(name="member", permissions=["read"])
        async_session.add(role)
        await async_session.commit()
        await async_session.refresh(role)
    return role

@pytest.mark.asyncio
async def test_create_role(async_client: AsyncClient):
    payload = {
        "name": "tester",
        "permissions": ["read", "write"]
    }
    response = await async_client.post("/api/v1/role", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "tester"
    assert set(data["permissions"]) == set(["read", "write"])

@pytest.mark.asyncio
async def test_get_role_by_id(async_client: AsyncClient, create_test_role):
    response = await async_client.get(f"/api/v1/role/{create_test_role.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == create_test_role.id
    assert data["name"] == create_test_role.name
    assert "permissions" in data

@pytest.mark.asyncio
async def test_get_nonexistent_role(async_client: AsyncClient):
    response = await async_client.get("/api/v1/role/99999999")
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_list_roles(async_client: AsyncClient):
    response = await async_client.get("/api/v1/role")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any("name" in role for role in data)

