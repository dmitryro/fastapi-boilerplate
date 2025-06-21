import pytest
from fastapi import status
from httpx._transports.asgi import ASGITransport
from httpx import AsyncClient
from app.main import app
import logging

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.fixture
async def async_client():
    # Setup HTTPX client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

# Tests for app/api/routes/api.py (prefix /api/v1)
@pytest.mark.asyncio
async def test_health_check(async_client):
    logger.debug("Sending GET request to /api/v1/health")
    response = await async_client.get(
        "/api/v1/health",
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok"}

@pytest.mark.asyncio
async def test_ask_success(async_client):
    question = "What is AI?"
    logger.debug(f"Sending GET request to /api/v1/ask with question={question}")
    response = await async_client.get(
        "/api/v1/ask",
        params={"question": question, "args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "asked", "question": question}

@pytest.mark.asyncio
async def test_ask_error(async_client):
    question = "What is AI?"
    logger.debug(f"Sending GET request to /api/v1/ask with question={question} and raise_error=True")
    response = await async_client.get(
        "/api/v1/ask",
        params={"question": question, "raise_error": True, "args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "Test error"

@pytest.mark.asyncio
async def test_ask_missing_question(async_client):
    logger.debug("Sending GET request to /api/v1/ask without question parameter")
    response = await async_client.get(
        "/api/v1/ask",
        params={"args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "question" in response.json()["detail"][0]["loc"]
    assert response.json()["detail"][0]["msg"] == "Field required"

@pytest.mark.asyncio
async def test_ask_short_question(async_client):
    question = "hi"
    logger.debug(f"Sending GET request to /api/v1/ask with question={question}")
    response = await async_client.get(
        "/api/v1/ask",
        params={"question": question, "args": "", "kwargs": ""}
    )

    logger.debug(f"Response status: {response.status_code}, body: {response.json()}")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "question" in response.json()["detail"][0]["loc"]
    assert "String should have at least 3 characters" in response.json()["detail"][0]["msg"]
