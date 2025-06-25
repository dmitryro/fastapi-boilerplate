import sys
import importlib
import pytest
from starlette.datastructures import Secret

@pytest.fixture
def restore_config_module():
    """Ensure app.core.config is reloaded fresh for each test."""
    if "app.core.config" in sys.modules:
        del sys.modules["app.core.config"]
    yield
    if "app.core.config" in sys.modules:
        del sys.modules["app.core.config"]

@pytest.mark.asyncio
async def test_secret_key_env_success(monkeypatch, restore_config_module):
    """Covers the try branch: SECRET_KEY is loaded from config successfully."""
    class DummyConfig:
        def __init__(self, *args, **kwargs):
            pass
        def __call__(self, key, cast=None, default=None):
            if key == "SECRET_KEY" and cast is not None:
                return Secret("supersecretfromenv")
            if cast is not None:
                # for int/bool etc. defaults
                return cast(default) if default is not None else cast()
            return default or "default"
    monkeypatch.setattr("starlette.config.Config", DummyConfig)
    import app.core.config as configmod
    assert isinstance(configmod.SECRET_KEY, Secret)
    assert str(configmod.SECRET_KEY) == "supersecretfromenv"

@pytest.mark.asyncio
async def test_secret_key_env_fallback(monkeypatch, restore_config_module):
    """Covers the except branch: SECRET_KEY fallback is used on exception."""
    class DummyConfig:
        def __init__(self, *args, **kwargs):
            pass
        def __call__(self, key, cast=None, default=None):
            if key == "SECRET_KEY":
                raise Exception("fail to load secret")
            if cast is not None:
                return cast(default) if default is not None else cast()
            return default or "default"
    monkeypatch.setattr("starlette.config.Config", DummyConfig)
    import app.core.config as configmod
    assert isinstance(configmod.SECRET_KEY, Secret)
    assert str(configmod.SECRET_KEY) == "testsecretkey1234567890"
