import importlib.util
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


MODULE_PATH = Path(__file__).parents[1] / "incident-response" / "app.py"


@pytest.fixture
def incident_module(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("incident_response_app", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "INCIDENTS_DIR", tmp_path)
    monkeypatch.setattr(
        module,
        "collect_logs",
        lambda endpoint: {"query": endpoint, "result": {"status": "ok"}},
    )
    monkeypatch.setattr(
        module,
        "collect_traces",
        lambda: {"query": "service.name=order-tracker", "result": {"status": "ok"}},
    )
    monkeypatch.setattr(
        module,
        "start_assistant",
        lambda path, record: {"status": "started", "pid": 1234},
    )
    return module


def test_alert_is_saved_with_context_and_starts_assistant(incident_module):
    payload = {
        "status": "firing",
        "receiver": "incident-response",
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "abc123",
                "labels": {"alertname": "Order Tracker 5xx responses"},
                "annotations": {
                    "endpoint": "/api/orders/{order_id}",
                    "time_window": "5 minutes",
                },
            }
        ],
    }

    with TestClient(incident_module.app) as client:
        response = client.post("/alerts", json=payload)

    assert response.status_code == 202
    record = json.loads((incident_module.INCIDENTS_DIR / "incident-abc123.json").read_text())
    assert record["endpoint"] == "/api/orders/{order_id}"
    assert record["enrichment"]["logs"]["result"]["status"] == "ok"
    assert record["enrichment"]["traces"]["result"]["status"] == "ok"
    assert record["assistant"]["status"] == "started"


def test_alert_requires_alerts_list(incident_module):
    with TestClient(incident_module.app) as client:
        response = client.post("/alerts", json={"status": "resolved"})

    assert response.status_code == 400
