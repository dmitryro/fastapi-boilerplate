import logging
import sys

from app.core.logging import InterceptHandler
from loguru import logger
from starlette.config import Config
from starlette.datastructures import Secret

# Load .env
config = Config(".env")

# Core App Settings
API_PREFIX = "/api/v1"
VERSION = "0.1.0"

# JWT / Auth
# Load SECRET_KEY as Starlette Secret, fallback default included
try:
    SECRET_KEY: Secret = config("SECRET_KEY", cast=Secret)
except Exception:
    SECRET_KEY = Secret("testsecretkey1234567890")

ALGORITHM: str = config("ALGORITHM", default="HS256")

ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES", cast=int, default=60)
DEBUG: bool = config("DEBUG", cast=bool, default=False)
MEMOIZATION_FLAG: bool = config("MEMOIZATION_FLAG", cast=bool, default=True)
DESCRIPTION: str = config("DESCRIPTION", default="NLP Project")
DOCS_URL: str = config("DOCS_URL", default="/api/v1/docs")
PROJECT_NAME: str = config("PROJECT_NAME", default="nlp-api")
JWT_ISSUER: str = config("JWT_ISSUER", default="BioIntelligence")

# DB Connection Pieces
POSTGRES_HOST: str = config("POSTGRES_HOST", default="127.0.0.1")
POSTGRES_PORT: str = config("POSTGRES_PORT", default="5432")
POSTGRES_USER: str = config("POSTGRES_USER", default="postgres")
POSTGRES_PASSWORD: str = config("POSTGRES_PASSWORD", default="password")
POSTGRES_DB: str = config("POSTGRES_DB", default="biodb")

# Full PostgreSQL URL for SQLAlchemy
DATABASE_URL: str = (
    f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# Connection Pooling
MAX_CONNECTIONS_COUNT: int = config("MAX_CONNECTIONS_COUNT", cast=int, default=10)
MIN_CONNECTIONS_COUNT: int = config("MIN_CONNECTIONS_COUNT", cast=int, default=10)

# Model & Paths
MODEL_PATH: str = config("MODEL_PATH", default="./ml/model/")
MODEL_NAME: str = config("MODEL_NAME", default="model.pkl")
INPUT_EXAMPLE: str = config("INPUT_EXAMPLE", default="./ml/model/questions/questions.json")

# Uvicorn settings
HOST: str = config("HOST", default="0.0.0.0")
PORT: int = config("PORT", cast=int, default=8080)
RELOAD: bool = config("RELOAD", cast=bool, default=True)

# Logging
LOGGING_LEVEL = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    handlers=[InterceptHandler(level=LOGGING_LEVEL)],
    level=LOGGING_LEVEL,
)
logger.configure(handlers=[{"sink": sys.stderr, "level": LOGGING_LEVEL}])

