import json
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.eval.heldout import FIXTURES, Observation, summarize
from backend.gateway import prompt_hook
from backend.main import app
from backend.pipeline.action_policy import evaluate_action
from backend.pipeline.policy import Decision
from backend.pipeline.retrieval import CLEAN, FLAGGED, load_notes
from backend.setup_chat_hooks import install_hook, install_retrieval
from backend.training.train_classifier import cases
from backend.victim_app.documents import DOCUMENT_EVENT_MARKER


def test_guarded_retrieval_sends_only_safe_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "notes.sqlite"))
    monkeypatch.setenv("PI_FIREWALL_NOTES_DIR", "")
    with TestClient(app, base_url="http://localhost") as client:
        assert {note["id"] for note in client.get("/api/guarded-notes").json()} == {
            "clean",
            "flagged",
        }
        clean = client.post("/api/guarded-notes/read", json={"note": "clean"}).json()
        flagged = client.post(
            "/api/guarded-notes/read", json={"note": "flagged"}
        ).json()
        assert CLEAN in clean["text"] and clean["decision"] == "allow"
        assert "withheld" in flagged["text"] and flagged["decision"] == "sanitize"
        assert (
            FLAGGED not in flagged["text"]
            and DOCUMENT_EVENT_MARKER not in flagged["text"]
        )
        assert (
            client.post(
                "/api/guarded-notes/read", json={"note": "../notes"}
            ).status_code
            == 422
        )
        assert DOCUMENT_EVENT_MARKER not in json.dumps(
            [row.reasons for row in app.state.store.recent()]
        )


def test_operator_selected_notes_load_only_regular_text_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "manual.md").write_text("A local operations note.", encoding="utf-8")
    (tmp_path / ".env").write_text("not available", encoding="utf-8")
    (tmp_path / "binary.png").write_bytes(b"not available")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.md").write_text("not available", encoding="utf-8")
    monkeypatch.setenv("PI_FIREWALL_NOTES_DIR", str(tmp_path))
    notes = load_notes()
    assert list(notes) == ["manual"]
    assert notes["manual"].body == "A local operations note."


@pytest.mark.parametrize(
    ("tool", "arguments", "decision"),
    [
        ("Read", {"file_path": "guide.md"}, "allow"),
        ("Read", {"file_path": "../guide.md"}, "deny"),
        ("Read", {"file_path": ".env.local"}, "deny"),
        ("Bash", {"command": "Get-Content -LiteralPath 'guide.md'"}, "allow"),
        ("Bash", {"command": "cat .env"}, "deny"),
        ("Bash", {"command": "Get-Location ; Get-Location"}, "review"),
        ("Write", {"file_path": "guide.md"}, "review"),
        ("Write", {"file_path": ".codex/hooks.json"}, "deny"),
        ("apply_patch", {"command": "*** Update File: .claude/settings.json"}, "deny"),
        ("mcp__firewall_notes__read_note", {"note": "clean"}, "allow"),
        ("WebFetch", {"url": "https://docs.example.invalid/help"}, "review"),
        ("WebFetch", {"url": "https://docs.example.invalid/?q=demo"}, "deny"),
    ],
)
def test_action_policy_classifies_tools(
    tmp_path: Path, tool: str, arguments: dict[str, str], decision: str
) -> None:
    assert (
        evaluate_action(
            tmp_path, "", tool, arguments, ("docs.example.invalid",)
        ).decision
        == decision
    )


@pytest.mark.parametrize(("source", "native"), [("codex", "deny"), ("claude", "ask")])
def test_tool_hook_holds_review_actions(
    monkeypatch: pytest.MonkeyPatch, source: str, native: str
) -> None:
    monkeypatch.setattr(
        prompt_hook,
        "request_json",
        lambda *args: {"decision": "review", "reason": "Approval required."},
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "cwd": "workspace",
        "tool_input": {"file_path": "draft.txt"},
    }
    result = prompt_hook.action_reply(source, 8010, json.dumps(event).encode())
    assert result["hookSpecificOutput"]["permissionDecision"] == native


def test_direct_read_cannot_bypass_guarded_notes(tmp_path: Path) -> None:
    notes = tmp_path / "reference"
    notes.mkdir()
    raw = evaluate_action(
        tmp_path,
        "",
        "Read",
        {"file_path": "reference/manual.md"},
        protected_roots=(notes,),
    )
    guarded = evaluate_action(
        tmp_path,
        "",
        "mcp__firewall_notes__read_note",
        {"note": "manual"},
        protected_roots=(notes,),
    )
    assert (raw.decision, guarded.decision) == ("deny", "allow")


def test_action_endpoint_redacts_tool_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "actions.sqlite"))
    monkeypatch.setenv("PI_FIREWALL_ACTION_ROOT", str(tmp_path))
    request = {
        "source": "claude",
        "cwd": str(tmp_path),
        "tool": "Write",
        "arguments": {"file_path": "draft.txt", "content": "UNPERSISTED_FIXTURE_TEXT"},
    }
    with TestClient(app, base_url="http://localhost") as client:
        assert (
            client.post("/api/inspect-action", json=request).json()["decision"]
            == "review"
        )
        record = app.state.store.recent()[0]
        assert record.original == "[claude tool request]"
        assert record.decision == "flag"
        assert "UNPERSISTED_FIXTURE_TEXT" not in json.dumps(record.reasons)


def test_desktop_install_merges_guarded_retrieval_and_tool_policy(
    tmp_path: Path,
) -> None:
    directory = tmp_path / ".codex"
    directory.mkdir()
    config = directory / "config.toml"
    config.write_text('model = "existing"\n', encoding="utf-8")
    install_retrieval(tmp_path, 8010)
    install_retrieval(tmp_path, 8011)
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["model"] == "existing"
    assert parsed["mcp_servers"]["firewall_notes"]["args"][-1] == "8011"
    path = install_hook(tmp_path, "codex", 8011, tool_guard=True)
    install_hook(tmp_path, "codex", 8011, tool_guard=True)
    groups = json.loads(path.read_text(encoding="utf-8"))["hooks"]
    assert set(groups) == {"UserPromptSubmit", "PreToolUse"}
    assert len(groups["PreToolUse"]) == 1


def test_heldout_prompt_text_is_absent_from_training() -> None:
    training = {row.text.casefold() for row in cases()}
    fixtures = [
        json.loads(line) for line in FIXTURES.read_text(encoding="utf-8").splitlines()
    ]
    assert len({row["id"] for row in fixtures}) == len(fixtures)
    assert not any(
        row["input"].casefold() in training
        for row in fixtures
        if row["surface"] == "prompt"
    )


def test_heldout_separates_alerts_from_prevention() -> None:
    result = summarize(
        [
            Observation("missed", True, Decision.ALLOW, 1),
            Observation("alert-only", True, Decision.FLAG, 3),
            Observation("held", True, Decision.BLOCK, 5),
            Observation("benign-false-hold", False, Decision.SANITIZE, 7),
        ]
    )
    assert result["alert_recall"] == pytest.approx(2 / 3)
    assert result["enforcement_recall"] == pytest.approx(1 / 3)
    assert result["false_holds"] == ["benign-false-hold"]
