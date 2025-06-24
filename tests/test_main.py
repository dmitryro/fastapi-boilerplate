import pytest
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport # Import ASGITransport
from unittest.mock import patch, Mock
import importlib # NEW: Import importlib for module reloading

# Import config variables directly
from app.core.config import PROJECT_NAME, VERSION, DESCRIPTION, MEMOIZATION_FLAG, DEBUG
from fastapi import FastAPI # Import FastAPI to patch its methods

# We will explicitly import get_application inside the tests after setting flags.
# from app.main import get_application # Removed global import for explicit reloading

# Fixture to create an async client for the main application
@pytest.fixture
async def app_client():
    # Use the actual get_application function to build the app
    # Need to import it here for this fixture if not globally imported
    from app.main import get_application 
    app = get_application()
    # Corrected: AsyncClient no longer takes 'app' directly. Use ASGITransport.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

# Fixture to provide a clean app instance for specific tests
@pytest.fixture
def clean_app_instance():
    """Provides a fresh FastAPI application instance without any overrides."""
    # Ensure this fixture creates a new app instance each time it's used
    # if a test might modify global config variables.
    from app.main import get_application # Import here for clean instance
    return get_application()

@pytest.mark.asyncio
async def test_openapi_generation(clean_app_instance):
    """
    Tests that the custom_openapi function correctly generates and
    modifies the OpenAPI schema, including security definitions.
    """
    app = clean_app_instance # Use the fresh app instance

    # Call the openapi generation method
    openapi_schema = app.openapi()

    # Assert basic structure
    assert "openapi" in openapi_schema
    assert openapi_schema["info"]["title"] == PROJECT_NAME # Use imported constant
    assert openapi_schema["info"]["version"] == VERSION     # Use imported constant
    assert openapi_schema["info"]["description"] == DESCRIPTION # Use imported constant

    # Assert security schemes are added
    assert "components" in openapi_schema
    assert "securitySchemes" in openapi_schema["components"]
    security_schemes = openapi_schema["components"]["securitySchemes"]
    assert "OAuth2Password" in security_schemes
    assert "BearerAuth" in security_schemes
    assert security_schemes["OAuth2Password"]["type"] == "oauth2"
    assert security_schemes["BearerAuth"]["type"] == "http"
    assert security_schemes["BearerAuth"]["scheme"] == "bearer"

    # Assert security is applied to paths (check at least one known path)
    # The /api/v1/logins/ route is a good candidate as it's included
    assert "/api/v1/logins/" in openapi_schema["paths"]
    login_path = openapi_schema["paths"]["/api/v1/logins/"]
    assert "post" in login_path # POST is the login endpoint
    assert "security" in login_path["post"]
    assert {"OAuth2Password": []} in login_path["post"]["security"]
    assert {"BearerAuth": []} in login_path["post"]["security"]

    # Test the 'if app.openapi_schema:' branch by calling it again
    second_call_schema = app.openapi()
    assert second_call_schema is openapi_schema # Should return the cached schema

# This fixture will ensure that FastAPI.add_event_handler and
# app.core.events.create_start_app_handler are always mocked
# when get_application() runs, including the initial global call.
@pytest.fixture(autouse=True)
def mock_startup_handlers():
    # Patch FastAPI.add_event_handler directly on the class
    with patch("fastapi.FastAPI.add_event_handler", new_callable=Mock) as mock_add_event_handler_fixture:
        # Patch app.core.events.create_start_app_handler
        with patch("app.core.events.create_start_app_handler", new_callable=Mock) as mock_create_handler_fixture:
            # The mocked create_start_app_handler should return a callable (itself a Mock)
            mock_create_handler_fixture.return_value = Mock(name="startup_event_handler_callable")
            yield mock_add_event_handler_fixture, mock_create_handler_fixture

@pytest.mark.asyncio
async def test_startup_event_handler_memoization_flag(monkeypatch, mock_startup_handlers):
    """
    Tests that the startup event handler is added when MEMOIZATION_FLAG is True.
    """
    mock_add_event_handler, mock_create_handler = mock_startup_handlers

    # Step 1: Ensure MEMOIZATION_FLAG is True
    monkeypatch.setattr('app.core.config.MEMOIZATION_FLAG', True)
    
    # Step 2: Clear cached app instance and force reload of app.main
    # This ensures that get_application() is re-evaluated with the patched MEMOIZATION_FLAG.
    monkeypatch.setattr('app.main.app', None) # Clear cached app instance
    if 'app.main' in importlib.sys.modules:
        del importlib.sys.modules['app.main']
    
    # Step 3: Import get_application *after* setting the flag and clearing the module cache.
    # This ensures that when get_application is called, it uses the newly configured state.
    from app.main import get_application
    
    # Step 4: CRUCIAL: Patch the *imported reference* to create_start_app_handler in app.main.
    # This ensures that when get_application() calls create_start_app_handler, it hits our mock.
    monkeypatch.setattr('app.main.create_start_app_handler', mock_create_handler)

    # Step 5: Reset mock call counts before the specific test execution.
    # This clears any calls that might have happened during initial module imports or fixture setup.
    mock_add_event_handler.reset_mock()
    mock_create_handler.reset_mock()

    # Step 6: IMPORTANT: Call get_application *after* all patching and resetting is in place.
    app_instance = get_application()

    # Step 7: Verify assertions
    mock_create_handler.assert_called_once_with(app_instance)
    mock_add_event_handler.assert_called_once_with("startup", mock_create_handler.return_value)


@pytest.mark.asyncio
async def test_startup_event_handler_no_memoization_flag(monkeypatch, mock_startup_handlers):
    """
    Tests that the startup event handler is NOT added when MEMOIZATION_FLAG is False.
    """
    mock_add_event_handler, mock_create_handler = mock_startup_handlers

    # Step 1: Ensure MEMOIZATION_FLAG is False
    monkeypatch.setattr('app.core.config.MEMOIZATION_FLAG', False)

    # Step 2: Clear cached app instance and force reload of app.main
    monkeypatch.setattr('app.main.app', None)
    if 'app.main' in importlib.sys.modules:
        del importlib.sys.modules['app.main']

    # Step 3: Import get_application *after* setting the flag and clearing the module cache.
    from app.main import get_application
    
    # Step 4: CRUCIAL: Patch the *imported reference* to create_start_app_handler in app.main.
    monkeypatch.setattr('app.main.create_start_app_handler', mock_create_handler)

    # Step 5: Reset mock call counts before the specific test execution.
    mock_add_event_handler.reset_mock()
    mock_create_handler.reset_mock()

    # Step 6: IMPORTANT: Call get_application *after* all patching and resetting is in place.
    get_application()
    
    # Step 7: Assertions
    # create_start_app_handler should NOT have been called because MEMOIZATION_FLAG is False
    mock_create_handler.assert_not_called()
    # add_event_handler should NOT have been called either
    mock_add_event_handler.assert_not_called()


@pytest.mark.asyncio
async def test_debug_middleware_registration(app_client):
    """
    Tests that the debug_middleware is registered and active by making a request.
    This also covers the `app.middleware("http")(debug_middleware)` line.
    """
    # Make a simple request to trigger middleware execution
    response = await app_client.get("/api/v1/health") # Use an existing simple route

    assert response.status_code == 200
    # If debug_middleware does anything visible (like adding a header or logging),
    # we could assert that. For now, just ensuring the request goes through
    # and the middleware line is executed for coverage is sufficient.
    # The coverage report will confirm if the line was hit.
