import base64
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.attacks.mutator import fixture_variants
from backend.config import Settings
from backend.main import app
from backend.pipeline.canary import contains_canary, new_canary
from backend.pipeline.conversation_state import SessionRisk, TokenBucket
from backend.pipeline.output_filter import entropy, inspect_output, unsafe_destination
from backend.victim_app.chat import Event, MockLLM, Turn
from backend.victim_app.ollama import Ollama


def test_canary_detects_known_encodings() -> None:
    marker = new_canary()
    encoded = base64.b64encode(marker.encode()).decode()
    assert marker != new_canary()
    assert contains_canary(encoded, marker)
    assert contains_canary(marker.encode().hex(), marker)
    assert contains_canary("".join(f"%{ord(c):02x}" for c in marker), marker)
    assert not contains_canary("This is a normal reply.", marker)
    assert not contains_canary("ordinary reply", "")
    assert marker in MockLLM(marker).reply(Turn("Demo metadata", Event.METADATA)).text


@pytest.mark.parametrize(
    ("value", "expected"), [("", 0), ("aaaa", 0), ("aabb", 1), ("abcd", 2)]
)
def test_entropy(value: str, expected: float) -> None:
    assert entropy(value) == expected


def test_outbound_links_respect_allowlist_and_query_policy() -> None:
    domains = ("example.invalid",)
    assert not unsafe_destination("https://example.invalid/help", domains)
    assert not unsafe_destination("#demo-image", domains)
    assert unsafe_destination("https://example.invalid/help?label=demo", domains)
    assert unsafe_destination("https://example.invalid.other.invalid/help", domains)
    assert unsafe_destination("file:///demo", domains)
    findings = inspect_output("![Example](https://unlisted.invalid/card)", "", domains)
    assert [reason.layer for reason in findings] == ["output"]


def test_conversation_risk_accumulates_and_decays() -> None:
    session = SessionRisk()
    assert session.add(0.5, 0, 10) == pytest.approx(0.275)
    assert session.add(0.5, 0, 10) == pytest.approx(0.55)
    assert session.add(0, 10, 10) == pytest.approx(0.275)


def test_token_bucket_caps_refill_and_limits_bursts() -> None:
    bucket = TokenBucket(2.0, 0)
    assert bucket.take()
    assert bucket.take()
    assert not bucket.take()
    bucket.refresh(2.5, 2, 5)
    assert not bucket.take()
    bucket.refresh(5, 2, 5)
    assert bucket.take()
    bucket.refresh(100, 2, 5)
    assert bucket.tokens == 2


def test_advanced_layer_blocks_output_and_limits_repeated_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "audit.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        app.state.settings = Settings(
            base_enabled=False, mid_enabled=False, block_capacity=1
        )
        response = client.post(
            "/v1/chat", json={"text": "Look up shipping", "document_ids": ["shipping"]}
        )
        assert response.json()["decision"] == "block"
        assert any(reason["layer"] == "output" for reason in response.json()["reasons"])
        limited = client.post("/v1/chat", json={"text": "Hello"})
        assert limited.status_code == 429
        assert limited.json()["reasons"][0]["layer"] == "rate_limit"
        assert len(app.state.store.recent()) == 2


def test_fixture_variants_cover_all_bundled_cases() -> None:
    variants = fixture_variants()
    assert len(variants) == 7
    assert all(len(rows) == 84 for rows in variants.values())
    assert len({case.id for rows in variants.values() for case in rows}) == 588


def test_local_provider_serializes_request_and_validates_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_client = httpx.Client

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://127.0.0.1:11434/api/chat"
        assert b"PI_CANARY_fixture" in request.content
        assert b"store hours" in request.content
        return httpx.Response(
            200, json={"message": {"content": "Support is open on weekdays."}}
        )

    def make_client(**kwargs: object) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handle))

    monkeypatch.setattr(httpx, "Client", make_client)
    assert (
        Ollama("demo", "PI_CANARY_fixture").reply(Turn("store hours")).text
        == "Support is open on weekdays."
    )
