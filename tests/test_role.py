# tests/test_role.py

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.core.db.session import get_db
from app.api.v1.models.role import Role
from app.api.v1.schemas.role import RoleCreate
from app.core.db.session import async_session_maker


@pytest.fixture
async def db_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@pytest.mark.asyncio
async def test_create_role(db_session: AsyncSession):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {"name": "editor", "permissions": ["read", "update"]}
        response = await ac.post("/api/v1/roles/", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "editor"
        assert "id" in data
        assert set(data["permissions"]) == {"read", "update"}


@pytest.mark.asyncio
async def test_get_role_by_id(db_session: AsyncSession):
    # Create a role first
    async with AsyncClient(app=app, base_url="http://test") as ac:
        payload = {"name": "viewer", "permissions": ["read"]}
        create_response = await ac.post("/api/v1/roles/", json=payload)
        role_id = create_response.json()["id"]

        # Get the role
        get_response = await ac.get(f"/api/v1/roles/{role_id}")
        assert get_response.status_code == 200
        assert get_response.json()["name"] == "viewer"


@pytest.mark.asyncio
async def test_get_nonexistent_role(db_session: AsyncSession):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/api/v1/roles/999999")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_roles(db_session: AsyncSession):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Ensure at least one role exists
        await ac.post("/api/v1/roles/", json={"name": "auditor", "permissions": ["read"]})
        response = await ac.get("/api/v1/roles/")
        assert response.status_code == 200
        roles = response.json()
        assert isinstance(roles, list)
        assert any(role["name"] == "auditor" for role in roles)

