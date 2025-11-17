import pytest # pyright: ignore[reportMissingImports]
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "database" in data

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "AiMsgHub" in response.text