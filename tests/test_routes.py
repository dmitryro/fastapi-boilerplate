from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app

client = TestClient(app)

def test_ask_success():
    response = client.post("/api/v1/ask", json={"question": "What does EVA do?"})
    assert response.status_code == 200
    assert "answer" in response.json()
    assert isinstance(response.json()["answer"], str)

def test_ask_empty():
    response = client.post("/api/v1/ask", json={"question": ""})
    assert response.status_code == 422  # Pydantic validation error

def test_ask_batch_success():
    notes = "Note: What does EVA do?\nNote: Tell me about Thoughtful AI's Agents."
    response = client.post("/api/v1/ask_batch", json={"question": notes})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert all("answer" in item for item in data)

def test_ask_batch_empty():
    response = client.post("/api/v1/ask_batch", json={"question": ""})
    assert response.status_code == 422  # Pydantic validation error

def test_ask_batch_invalid_format():
    response = client.post("/api/v1/ask_batch", json={"question": "This text has no note prefix"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0].get("answer") == "No valid ICD-10 codes detected"

def test_ask_get_success():
    response = client.get("/api/v1/ask", params={"question": "What does EVA do?"})
    assert response.status_code == 200
    assert "answer" in response.json()

def test_ask_get_missing_param():
    response = client.get("/api/v1/ask")
    assert response.status_code == 422  # Query param validation

def test_ask_get_too_short():
    response = client.get("/api/v1/ask", params={"question": "ab"})
    assert response.status_code == 422  # min_length=3 validation

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# --- New tests to cover missing lines in routes.py ---

def test_ask_get_exception():
    with patch("app.api.v1.routes.query_llm", side_effect=Exception("LLM failure")):
        response = client.get("/api/v1/ask", params={"question": "Hello"})
        assert response.status_code == 500
        assert "LLM failure" in response.json()["detail"]

def test_ask_post_exception():
    with patch("app.api.v1.routes.query_llm", side_effect=Exception("LLM failure")):
        response = client.post("/api/v1/ask", json={"question": "Hello"})
        assert response.status_code == 500
        assert "LLM failure" in response.json()["detail"]

def test_ask_batch_no_valid_notes():
    response = client.post("/api/v1/ask_batch", json={"question": "Note:"})
    assert response.status_code == 400
    assert response.json()["detail"] == "No valid notes found in input"

def test_ask_batch_generic_exception():
    with patch("app.api.v1.routes.query_llm", side_effect=Exception("Batch LLM failure")):
        response = client.post("/api/v1/ask_batch", json={"question": "Note: Something"})
        assert response.status_code == 500
        assert "Batch LLM failure" in response.json()["detail"]

