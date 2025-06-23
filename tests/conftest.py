import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from app.core.db import Base
from app.main import app

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
