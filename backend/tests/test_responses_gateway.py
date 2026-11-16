import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.gateway import responses
from backend.main import app
from backend.victim_app.chat import DEMO_MARKER
from backend.victim_app.documents import DOCUMENT_EVENT_MARKER


@dataclass
class LocalUpstream:
    requests: list[httpx.Request] = field(default_factory=list)
    status: int = 200
    media: str = "application/json"
    content: bytes = b'{"object":"response","output":[]}'

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(
            self.status, headers={"content-type": self.media}, content=self.content
        )


@pytest.fixture
def gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[TestClient, LocalUpstream]]:
    upstream = LocalUpstream()
    real_client = httpx.AsyncClient

    def make_client(**kwargs: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(upstream.handle), **kwargs)

    monkeypatch.setenv("PI_FIREWALL_RESPONSES_UPSTREAM", "http://127.0.0.1:9021")
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "gateway.sqlite"))
    monkeypatch.setattr(responses.httpx, "AsyncClient", make_client)
    with TestClient(app, base_url="http://localhost") as client:
        yield client, upstream


def test_responses_rewrites_only_the_flagged_tool_result(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    clean = "Hours\n  The office is open weekdays."
    bad = f"Archived fixture only. <!-- {DOCUMENT_EVENT_MARKER} -->"
    payload = {
        "model": "local-test",
        "instructions": "You are a retail support assistant.",
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "What are the office hours?"}
                ],
            },
            {"type": "function_call_output", "call_id": "call_clean", "output": clean},
            {"type": "function_call_output", "call_id": "call_flagged", "output": bad},
        ],
        "stream": False,
        "store": False,
    }
    result = client.post(
        "/v1/responses", json=payload, headers={"Authorization": "Bearer test-only"}
    )
    assert result.status_code == 200
    assert result.headers["X-PI-Firewall-Decision"] == "sanitize"
    request = upstream.requests[0]
    assert request.url == "http://127.0.0.1:9021/v1/responses"
    assert "authorization" not in request.headers
    expected = payload["input"]
    expected[2]["output"] = responses.WITHHELD_DOCUMENT
    assert json.loads(request.content) == payload
    assert bad not in request.content.decode()
    records = app.state.store.recent()
    assert [(row.original, row.normalized, row.decision) for row in records] == [
        ("[Responses API request]", "", "sanitize")
    ]
    assert any(
        reason.get("category") == "indirect_injection" for reason in records[0].reasons
    )
    assert (
        DOCUMENT_EVENT_MARKER.casefold()
        not in json.dumps(records[0].reasons).casefold()
    )


def test_responses_cleans_text_parts_and_shell_output(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    bad = f"<!-- {DOCUMENT_EVENT_MARKER} -->"
    result = client.post(
        "/v1/responses",
        json={
            "model": "local-test",
            "input": [
                {
                    "type": "custom_tool_call_output",
                    "call_id": "call_part",
                    "output": [
                        {
                            "type": "input_text",
                            "text": "Keep this note. <!-- preview -->",
                        },
                        {"type": "input_text", "text": bad},
                    ],
                },
                {
                    "type": "shell_call_output",
                    "call_id": "call_shell",
                    "output": [
                        {
                            "stdout": "Keep stdout.\n",
                            "stderr": bad,
                            "outcome": {"type": "exit", "exit_code": 0},
                        },
                    ],
                },
            ],
        },
    )
    assert result.status_code == 200
    parts, shell = json.loads(upstream.requests[0].content)["input"]
    assert "Keep this note." in parts["output"][0]["text"]
    assert "preview" not in parts["output"][0]["text"]
    assert parts["output"][1]["text"] == responses.WITHHELD_DOCUMENT
    assert shell["output"][0] == {
        "stdout": "Keep stdout.\n",
        "stderr": responses.WITHHELD_DOCUMENT,
        "outcome": {"type": "exit", "exit_code": 0},
    }


def test_responses_blocks_prompt_before_upstream(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    text = next(iter(app.state.cases.values())).text
    result = client.post("/v1/responses", json={"model": "local-test", "input": text})
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "firewall_blocked"
    assert upstream.requests == []


def sse(*events: dict[str, Any]) -> bytes:
    return "".join(f"data: {json.dumps(event)}\r\n\r\n" for event in events).encode()


def test_response_blocks_unapproved_destination_in_tool_arguments(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    arguments = json.dumps(
        {"payload": [{"url": "https://unapproved.example.invalid/preview"}]}
    )
    upstream.content = json.dumps(
        {
            "object": "response",
            "output": [
                {"type": "function_call", "name": "fixture", "arguments": arguments},
            ],
        }
    ).encode()
    response = client.post(
        "/v1/responses", json={"model": "local-test", "input": "Hello."}
    )
    assert response.status_code == 400
    assert "unapproved.example.invalid" not in response.text


def test_response_holds_split_tool_argument_deltas_before_delivery(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    upstream.media = "text/event-stream"
    arguments = json.dumps({"reference": DEMO_MARKER})
    split = arguments.index(DEMO_MARKER) + 13
    upstream.content = sse(
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "fc_fixture",
            "delta": arguments[:split],
        },
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "fc_fixture",
            "delta": arguments[split:],
        },
        {
            "type": "response.completed",
            "response": {"object": "response", "output": []},
        },
    )
    response = client.post(
        "/v1/responses", json={"model": "local-test", "input": "Hello.", "stream": True}
    )
    assert response.status_code == 400
    assert DEMO_MARKER[:12] not in response.text


def test_response_preserves_benign_tool_arguments(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    upstream.content = json.dumps(
        {
            "object": "response",
            "output": [
                {
                    "type": "function_call",
                    "name": "fixture",
                    "arguments": json.dumps({"note": "clean"}),
                },
            ],
        }
    ).encode()
    response = client.post(
        "/v1/responses", json={"model": "local-test", "input": "Hello."}
    )
    assert response.status_code == 200
    assert response.content == upstream.content


def test_responses_releases_clean_sse_unchanged(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    upstream.media = "text/event-stream"
    upstream.content = sse(
        {"type": "response.output_text.delta", "delta": "Clean fixture text."},
        {
            "type": "response.completed",
            "response": {"object": "response", "output": []},
        },
    )
    result = client.post(
        "/v1/responses", json={"model": "local-test", "input": "Hello.", "stream": True}
    )
    assert result.status_code == 200
    assert result.headers["X-PI-Firewall-Decision"] == "allow"
    assert result.content == upstream.content
    assert "upstream-first-body-byte;dur=" in result.headers["Server-Timing"]
    assert "gateway-total;dur=" in result.headers["Server-Timing"]


def test_responses_withholds_split_synthetic_marker_before_streaming(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    upstream.media = "text/event-stream"
    upstream.content = sse(
        {"type": "response.output_text.delta", "delta": DEMO_MARKER[:12]},
        {"type": "response.output_text.delta", "delta": DEMO_MARKER[12:]},
        {
            "type": "response.completed",
            "response": {"object": "response", "output": []},
        },
    )
    result = client.post(
        "/v1/responses", json={"model": "local-test", "input": "Hello.", "stream": True}
    )
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "firewall_blocked"
    assert DEMO_MARKER[:12] not in result.text


def test_responses_discards_incomplete_wire_and_untrusted_errors(
    gateway: tuple[TestClient, LocalUpstream],
) -> None:
    client, upstream = gateway
    upstream.media = "text/event-stream"
    upstream.content = sse({"type": "response.output_text.delta", "delta": "preview"})
    data = {"model": "local-test", "input": "Hello.", "stream": True}
    assert (
        client.post("/v1/responses", json=data).json()["error"]["code"]
        == "invalid_upstream"
    )
    upstream.status = 500
    upstream.content = b"internal diagnostic"
    result = client.post("/v1/responses", json=data)
    assert result.status_code == 502
    assert "internal diagnostic" not in result.text


def test_responses_checks_format_and_request_size(
    gateway: tuple[TestClient, LocalUpstream], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, upstream = gateway
    assert client.post("/v1/responses", content=b"{").status_code == 400
    assert (
        client.post(
            "/v1/responses", json={"model": "local-test", "input": [{"type": {}}]}
        ).status_code
        == 400
    )
    asynchronous = client.post(
        "/v1/responses", json={"model": "local-test", "background": True}
    )
    assert asynchronous.json()["error"]["code"] == "background_unsupported"
    monkeypatch.setattr(responses, "MAX_BODY", 8)
    assert client.post("/v1/responses", json={"model": "local-test"}).status_code == 413
    assert not upstream.requests


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid:9021",
        "https://127.0.0.1:9021",
        "http://127.0.0.1:9021/path",
        "http://127.0.0.1:9021/?q=1",
        "http://name:dummy@127.0.0.1:9021",
    ],
)
def test_responses_upstream_is_a_configured_loopback_origin(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setenv("PI_FIREWALL_RESPONSES_UPSTREAM", url)
    with pytest.raises(ValueError, match="127.0.0.1"):
        responses.configured_upstream()
