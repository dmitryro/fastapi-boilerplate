import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from typing import AsyncGenerator

# Import components from sqlalchemy for type hinting and patching targets
from sqlalchemy.ext.asyncio import AsyncSession
# Import the specific function to be tested
from app.core.db.session import get_db

# This fixture mocks the DATABASE_URL to a test-specific in-memory SQLite URL for isolation.
# It ensures that no actual database connection is attempted during these tests.
# This fixture remains as it's part of the test file and good practice for isolation.
@pytest.fixture(autouse=True)
def mock_database_url(monkeypatch):
    """
    Mocks the DATABASE_URL to a test-specific PostgreSQL-like URL for isolation.
    Uses autouse=True to ensure this patch is applied automatically to all tests
    in this module.
    """
    # Changed to a dummy PostgreSQL connection string for consistency
    monkeypatch.setattr("app.core.config.DATABASE_URL", "postgresql+asyncpg://test_user:test_password@localhost:5432/test_db")

@pytest.mark.asyncio
async def test_get_db_yields_session_and_closes_it():
    """
    Tests that the `get_db` asynchronous generator:
    1. Yields an AsyncSession instance.
    2. Ensures that the session's `close()` method is called upon exiting the generator.

    This test properly consumes `get_db` (which is an async generator, not an async context manager)
    using an `async for` loop and mocks `AsyncSessionLocal` to control the session behavior.
    """
    # Create a MagicMock for the session instance.
    # We will explicitly define its async context manager methods.
    mock_session = MagicMock()
    
    # Configure `__aenter__` to be an AsyncMock that returns `mock_session` itself.
    # This is crucial because `async with` will assign the result of `__aenter__` to the 'as' variable.
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    
    # Configure `__aexit__` to be an AsyncMock that returns None (standard for context managers not suppressing exceptions).
    mock_session.__aexit__ = AsyncMock(return_value=None)
    
    # Explicitly make the `close` method an AsyncMock so we can track its awaited calls.
    mock_session.close = AsyncMock()

    # Patch `AsyncSessionLocal` (the *factory* that `get_db` calls) with a MagicMock.
    # This mock represents the `sessionmaker` instance itself.
    mock_session_factory = MagicMock()
    
    # Configure the `mock_session_factory` to return our `mock_session` when it's called.
    # This simulates `AsyncSessionLocal()` returning an async session instance.
    mock_session_factory.return_value = mock_session

    # Patch `app.core.db.session.AsyncSessionLocal` with our controlled mock factory.
    # This ensures that `get_db` uses our mock when it tries to create a session.
    with patch("app.core.db.session.AsyncSessionLocal", new=mock_session_factory):
        # Consume the asynchronous generator using 'async for'.
        # The 'async for' loop handles the iteration and implicit cleanup of the generator.
        async for session in get_db():
            # Assert that the yielded session is our intended mock session.
            assert session is mock_session
            # `session.close()` should NOT have been called yet, as we are still inside the consuming loop.
            mock_session.close.assert_not_awaited()

        # After the `async for` loop finishes (or is broken),
        # the `finally` block within `get_db` should have executed, calling `session.close()`.
        # Assert that `session.close()` was called exactly once.
        mock_session.close.assert_awaited_once()
        
        # Verify that AsyncSessionLocal was called to create the session
        mock_session_factory.assert_called_once()


@pytest.mark.asyncio
async def test_get_db_exception_handling():
    """
    Tests that if an exception occurs within the `get_db`'s consumer,
    the session's `close()` method is still called due to the `finally` block in `get_db`.

    This test uses `async for` to consume the generator and `pytest.raises` to catch
    the simulated exception, ensuring cleanup is still performed.
    """
    # Create a MagicMock for the session instance.
    mock_session = MagicMock()
    
    # Configure `__aenter__` to be an AsyncMock that returns `mock_session` itself.
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    
    # Configure `__aexit__` to be an AsyncMock that returns False (to propagate the exception).
    # If it returned True, it would suppress the exception. None would also propagate by default.
    mock_session.__aexit__ = AsyncMock(return_value=False)
    
    # Explicitly make the `close` method an AsyncMock.
    mock_session.close = AsyncMock()

    # Patch `AsyncSessionLocal` (the *factory*) with a MagicMock.
    mock_session_factory = MagicMock()
    # Configure the `mock_session_factory` to return our `mock_session` when it's called.
    mock_session_factory.return_value = mock_session

    with patch("app.core.db.session.AsyncSessionLocal", new=mock_session_factory):
        # Manually get the async generator object
        gen = get_db()
        
        # We expect a ValueError to be raised.
        # `pytest.raises` will catch this exception.
        with pytest.raises(ValueError, match="Simulated error in DB operation"):
            # Manually advance the generator to get the session
            session = await gen.__anext__() # This is equivalent to the first yield of an async for
            
            assert session is mock_session
            
            # Simulate an error by throwing it back into the generator.
            # This will cause the generator's `finally` block (and thus `session.close()`) to execute.
            await gen.athrow(ValueError("Simulated error in DB operation"))
        
        # After `pytest.raises` has caught the exception and the generator's `athrow`
        # has completed its cleanup, `session.close()` should have been called.
        # Assert that `session.close()` was called exactly once.
        mock_session.close.assert_awaited_once()
        
        # Verify that AsyncSessionLocal was called to create the session
        mock_session_factory.assert_called_once()
