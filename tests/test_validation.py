import pytest
from pydantic import ValidationError
from app.api.v1.validation import AskRequest

def test_valid_question():
    model = AskRequest(question="What is EVA?")
    assert model.question == "What is EVA?"

def test_invalid_question():
    with pytest.raises(ValidationError):
        AskRequest(question="")  # Should fail due to empty string
