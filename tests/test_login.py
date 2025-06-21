import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
from fastapi import status
from unittest.mock import AsyncMock, patch, ANY

from app.main import app


@pytest.mark.asyncio
@patch("app.api.v1.services.login.LoginService.authenticate_user", new_callable=AsyncMock)
async def test_login_success(mock_authenticate_user):
    mock_authenticate_user.return_value = {
        "access_token": "fake-token",
        "token_type": "bearer"
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/logins/", json={
            "username": "testuser",
            "password": "testpass"
        })

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "access_token": "fake-token",
        "token_type": "bearer"
    }
    mock_authenticate_user.assert_awaited_once_with("testuser", "testpass", ANY)


@pytest.mark.asyncio
@patch("app.api.v1.services.login.LoginService.authenticate_user", new_callable=AsyncMock)
async def test_login_wrong_password(mock_authenticate_user):
    mock_authenticate_user.return_value = None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/logins/", json={
            "username": "testuser",
            "password": "wrongpass"
        })

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Incorrect username or password"
    mock_authenticate_user.assert_awaited_once_with("testuser", "wrongpass", ANY)


@pytest.mark.asyncio
@patch("app.api.v1.services.login.LoginService.authenticate_user", new_callable=AsyncMock)
async def test_login_nonexistent_user(mock_authenticate_user):
    mock_authenticate_user.return_value = None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/logins/", json={
            "username": "ghostuser",
            "password": "somepass"
        })

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Incorrect username or password"
    mock_authenticate_user.assert_awaited_once_with("ghostuser", "somepass", ANY)

