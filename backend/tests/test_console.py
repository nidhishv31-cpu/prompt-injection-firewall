from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import app


def test_console_routes_use_local_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "console.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        assert (
            client.get("/api/rules", headers={"Host": "example.invalid"}).status_code
            == 400
        )
        assert len(client.get("/api/documents").json()) == 20
        assert len(client.get("/api/lab").json()) == 84
        lab = client.post("/api/lab", json={"case_id": "META-01"}).json()
        assert (lab["off_disclosures"], lab["on_disclosures"]) == (1, 0)
        assert (
            client.post("/api/lab", json={"case_id": "custom-text"}).status_code == 404
        )
        scan = client.post(
            "/api/scan", json={"text": "<i hidden>Hidden</i><b>Visible</b>"}
        ).json()
        assert "Visible" in scan["text"] and "Hidden" not in scan["text"]
        assert len(client.get("/api/model").json()["predictions"]) == 43
        client.post("/v1/chat", json={"text": "Can I use a gift receipt?"})
        assert client.get("/api/dashboard").json()["total"] == 1


def test_rules_round_trip_and_reject_invalid_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "rules.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        rules = client.get("/api/rules").json()
        rules["flag_threshold"] = 0.31
        assert client.put("/api/rules", json=rules).status_code == 200
        assert (
            client.put("/api/rules", json={**rules, "block_threshold": 0.1}).status_code
            == 422
        )
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/rules").json()["flag_threshold"] == 0.31
