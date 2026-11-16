import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.gateway import prompt_hook
from backend.main import app
from backend.setup_chat_hooks import install_hook


def event(prompt: str) -> bytes:
    return json.dumps(
        {
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
            "transcript_path": "not-sent.jsonl",
        }
    ).encode()


@pytest.mark.parametrize(
    ("decision", "blocked"),
    [
        ("allow", False),
        ("flag", False),
        ("sanitize", True),
        ("block", True),
    ],
)
def test_prompt_hook_returns_native_decision(
    monkeypatch: pytest.MonkeyPatch, decision: str, blocked: bool
) -> None:
    inspect = Mock(return_value=decision)
    monkeypatch.setattr(prompt_hook, "inspect_prompt", inspect)
    result = prompt_hook.hook_reply("codex", 8000, event("Hello."))
    assert (result.get("decision") == "block") is blocked
    inspect.assert_called_once_with("codex", 8000, "Hello.")


def test_prompt_hook_stops_when_service_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(prompt_hook, "inspect_prompt", Mock(side_effect=OSError))
    result = prompt_hook.hook_reply("claude", 8020, event("Hello."))
    assert result["decision"] == "block"
    assert "8020" in result["reason"]


def test_prompt_endpoint_evaluates_without_calling_a_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "hooks.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        first = client.post(
            "/api/inspect-prompt",
            json={"source": "codex", "text": "What are the store hours?"},
        )
        test_text = next(iter(app.state.cases.values())).text
        second = client.post(
            "/api/inspect-prompt", json={"source": "claude", "text": test_text}
        )
        assert [item.json()["decision"] for item in (first, second)] == [
            "allow",
            "block",
        ]
        rows = app.state.store.recent()
        assert [row.original for row in rows] == [
            "[claude chat prompt]",
            "[codex chat prompt]",
        ]
        assert all(not row.normalized for row in rows)
        assert test_text not in json.dumps([row.reasons for row in rows])


def test_hook_install_preserves_other_settings_and_is_idempotent(
    tmp_path: Path,
) -> None:
    other = {"hooks": [{"type": "command", "command": "existing-hook"}]}
    target = tmp_path / ".claude" / "settings.local.json"
    target.parent.mkdir()
    target.write_text(
        json.dumps({"model": "existing", "hooks": {"UserPromptSubmit": [other]}})
    )
    install_hook(tmp_path, "claude", 8000)
    initial = target.read_bytes()
    install_hook(tmp_path, "claude", 8000)
    assert target.read_bytes() == initial
    installed = json.loads(initial)
    assert installed["model"] == "existing"
    assert installed["hooks"]["UserPromptSubmit"][0] == other
    install_hook(tmp_path, "claude", 8999)
    assert len(json.loads(target.read_text())["hooks"]["UserPromptSubmit"]) == 2
    assert "8999" in target.read_text()
