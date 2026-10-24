import pytest
from fastapi.testclient import TestClient
from vetaal.web import webui
from vetaal.web.webui import app
from vetaal.utils.db import DatabaseManager

client = TestClient(app)

def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200


def test_api_health_reflects_real_state(tmp_path):
    """Before this fix, /api/health was hardcoded to always return
    {'status': 'ok', 'phase': 'IDLE'} regardless of what the agent was
    actually doing. It must now reflect real, persisted agent state."""
    db = DatabaseManager(str(tmp_path / "health_test.db"))
    webui.set_database_manager(db)
    try:
        db.upsert_state({"phase": "ENUMERATION", "error": ""})
        resp = client.get("/api/health")
        data = resp.json()
        assert data["phase"] == "ENUMERATION"
        assert data["status"] == "ok"

        db.upsert_state({"phase": "ENUMERATION", "error": "nmap not found"})
        resp2 = client.get("/api/health")
        data2 = resp2.json()
        assert data2["status"] == "degraded"
        assert "nmap not found" in data2["last_error"]
    finally:
        webui.set_database_manager(None)
