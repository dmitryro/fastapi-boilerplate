from pydantic import ValidationError
from app.api.v1.schemas.login import LoginRequest


def validate_login(data: dict) -> LoginRequest:
    """
    Validate login data against the LoginRequest schema.
    Raises ValidationError if invalid.
    """
    try:
        login = LoginRequest(**data)
    except ValidationError as e:
        raise e
    return login

