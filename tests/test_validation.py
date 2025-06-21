# tests/test_validation.py

import pytest
from pydantic import ValidationError
from app.api.v1.schemas.login import LoginRequest  # ✅ use the actual model

def test_valid_question():
    model = LoginRequest(username="eva_user", password="secret123")
    assert model.username == "eva_user"

def test_invalid_question():
    with pytest.raises(ValidationError):
        LoginRequest(username="", password="")  # Assuming min_length validation

