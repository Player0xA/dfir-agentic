import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import json
import uuid

# We must import the app from our new module
from tools.dashboard.dashboard_server import app, SETTINGS_FILE

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    # The root should serve our HTML shell
    assert "text/html" in response.headers["content-type"]
    assert "DFIR-Agentic Dashboard" in response.text

def test_list_cases_endpoint():
    # Even if empty, it should return a 200 with a cases list
    response = client.get("/api/cases")
    assert response.status_code == 200
    data = response.json()
    assert "cases" in data
    assert isinstance(data["cases"], list)

def test_missing_case_404():
    fake_id = str(uuid.uuid4())
    response = client.get(f"/api/cases/{fake_id}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Case not found"

def test_settings_persistence():
    # Test POSTing new layout settings
    test_layout = [
        {"id": "test_panel", "x": 0, "y": 0, "w": 4, "h": 4}
    ]
    
    post_resp = client.post("/api/settings", json=test_layout)
    assert post_resp.status_code == 200
    assert post_resp.json()["status"] == "success"
    
    # Test GETting them back
    get_resp = client.get("/api/settings")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    
    assert len(retrieved) == 1
    assert retrieved[0]["id"] == "test_panel"
