# tests/conftest.py
import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import AsyncMock
from app.core.db import Base
from app.main import app
from app.core.db.session import get_db


@pytest.fixture
async def async_session_maker():
    engine = create_async_engine("postgresql+asyncpg://localhost", echo=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    AsyncSessionMaker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield AsyncSessionMaker
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(async_session_maker):
    async with async_session_maker() as session:
        yield session


@pytest.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def mock_db():
    """Mock AsyncSession for database interactions."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.rollback = AsyncMock()
    mock_session.add = AsyncMock()
    mock_session.refresh = AsyncMock()
    return mock_session


@pytest.fixture(autouse=True)
def override_get_db(mock_db):
    async def mock_get_db():
        yield mock_db
    app.dependency_overrides[get_db] = mock_get_db
