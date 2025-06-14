from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.api.v1.routes.api import router as api_router
from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.user import router as user_router
from app.api.v1.routes.role import router as role_router
from app.api.v1.routes.registration import router as registration_router
from app.api.v1.routes.login import router as login_router

from app.core.config import (
    PROJECT_NAME,
    VERSION,
    DESCRIPTION,
    DEBUG,
    DOCS_URL,
    API_PREFIX,
    MEMOIZATION_FLAG,
)
from app.core.events import create_start_app_handler


def custom_openapi(app: FastAPI):
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2Password": {
            "type": "oauth2",
            "flows": {
                "password": {
                    "tokenUrl": "/api/v1/auth/login",
                    "scopes": {}
                }
            }
        },
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    # Apply both options globally to all paths
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation["security"] = [
                {"OAuth2Password": []},
                {"BearerAuth": []}
            ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


def get_application() -> FastAPI:
    app = FastAPI(
        title=PROJECT_NAME,
        debug=DEBUG,
        version=VERSION,
        description=DESCRIPTION,
        docs_url=DOCS_URL,
        swagger_ui_init_oauth={"persistAuthorization": True},
    )

    # Public health and ask endpoints
    app.include_router(api_router, prefix=API_PREFIX)

    # Authentication endpoints
    app.include_router(auth_router, prefix=f"{API_PREFIX}/auth")

    # Protected CRUD endpoints
    app.include_router(user_router, prefix=f"{API_PREFIX}/users")
    app.include_router(role_router, prefix=f"{API_PREFIX}/roles")
    app.include_router(registration_router, prefix=f"{API_PREFIX}/registrations")
    app.include_router(login_router, prefix=f"{API_PREFIX}/logins")

    # Startup events
    if MEMOIZATION_FLAG:
        app.add_event_handler("startup", create_start_app_handler(app))

    # Override OpenAPI schema generation with OAuth2 password flow
    app.openapi = lambda: custom_openapi(app)

    return app


app = get_application()

