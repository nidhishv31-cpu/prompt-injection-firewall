import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend import testing_approvals
from backend.gateway import prompt_hook
from backend.gateway.testing_scope import operator_path, read_scope
from backend.main import app
from backend.setup_chat_hooks import configure_test_scope, install_hook

PATCH = (
    "*** Begin Patch\n*** Update File: notes.md\n@@\n-before\n+after\n*** End Patch\n"
)


@pytest.fixture
def environment(tmp_path, monkeypatch):
    scope_path = tmp_path / "local" / "test.json"
    notes = tmp_path / "notes.md"
    notes.write_text("before\n", encoding="utf-8")
    session = uuid4()
    configure_test_scope(scope_path, session)
    scope = read_scope(scope_path)
    assert scope is not None
    monkeypatch.setenv("PI_FIREWALL_TEST_SCOPE", str(scope_path))
    monkeypatch.setenv("PI_FIREWALL_ACTION_ROOT", str(tmp_path))
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "audit.sqlite3"))
    hook = {"X-Firewall-Session": str(session), "X-Firewall-Hook-Key": scope.hook_key}
    operator = {
        "Authorization": "Bearer " + operator_path(scope_path).read_text().strip()
    }
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client, scope_path, hook, operator, notes


def action(client, headers, patch=PATCH, provider="codex"):
    return client.post(
        "/api/inspect-action",
        headers=headers,
        json={
            "source": provider,
            "tool": "apply_patch",
            "arguments": {"command": patch},
        },
    )


def test_other_chats_skip_before_network(environment, monkeypatch):
    client, scope_path, hook, _, _ = environment
    outbound = []

    def send(_port, method, route, body, *, headers):
        outbound.append(route)
        return client.request(method, route, headers=headers, json=body).json()

    monkeypatch.setattr(prompt_hook, "request_json", send)
    for app_name, session in [
        ("codex", str(uuid4())),
        ("claude", hook["X-Firewall-Session"]),
        ("codex", None),
    ]:
        for kind, event in [
            ("prompt", {"hook_event_name": "UserPromptSubmit", "prompt": "Hello"}),
            (
                "tool",
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "apply_patch",
                    "tool_input": {"command": PATCH},
                },
            ),
        ]:
            assert (
                prompt_hook.dispatch(
                    app_name,
                    8010,
                    kind,
                    json.dumps({**event, "session_id": session}).encode(),
                    scope_path,
                )
                == {}
            )
    assert outbound == []
    event = {
        "session_id": hook["X-Firewall-Session"],
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Hello",
    }
    raw = json.dumps(event).encode()
    assert prompt_hook.dispatch("codex", 8010, "prompt", raw, scope_path) == {}
    assert outbound == ["/api/inspect-prompt"]
    configure_test_scope(scope_path, None)
    assert prompt_hook.dispatch("codex", 8010, "prompt", raw, scope_path) == {}
    assert outbound == ["/api/inspect-prompt"]


def test_single_use_approval_and_other_sessions(environment):
    client, scope_path, hook, operator, _ = environment
    route = "/api/testing-approvals"
    other_chat = {**hook, "X-Firewall-Session": str(uuid4())}
    assert client.get(route).status_code == 401
    assert action(client, other_chat).status_code == 403
    assert action(client, hook, provider="claude").status_code == 403
    assert action(client, {**hook, "X-Firewall-Hook-Key": "wrong"}).status_code == 403
    assert action(client, {}).json()["decision"] == "review"
    assert client.get(route, headers=operator).json()["entries"] == []

    assert action(client, hook).json()["decision"] == "review"
    row = client.get(route, headers=operator).json()["entries"][0]
    assert row["status"] == "pending"
    assert row["patch"] == PATCH
    approve = f"{route}/{row['id']}/approve"
    assert client.post(approve, headers=hook).status_code == 401
    assert client.post(approve, headers=operator).json()["status"] == "approved"
    assert client.post(approve, headers=operator).status_code == 409
    assert action(client, other_chat).status_code == 403
    assert action(client, {}).json()["decision"] == "review"

    with ThreadPoolExecutor(max_workers=4) as pool:
        decisions = list(
            pool.map(lambda _: action(client, hook).json()["decision"], range(4))
        )
    assert decisions.count("allow") == 1
    assert decisions.count("deny") == 3
    rows = client.get(route, headers=operator).json()["entries"]
    assert [(row["status"], row["patch"]) for row in rows] == [("consumed", "")]
    assert any("approved" in str(row.reasons) for row in app.state.store.recent())

    configure_test_scope(scope_path, uuid4())
    assert action(client, hook).status_code == 403
    assert client.get(route, headers=operator).json()["entries"] == []


def test_patch_mutation_expiry_decline_and_protected_paths(environment, monkeypatch):
    client, _, hook, operator, notes = environment
    route = "/api/testing-approvals"
    now = [1000.0]
    monkeypatch.setattr(testing_approvals, "time", lambda: now[0])

    assert (
        action(client, hook, PATCH.replace("notes.md", ".codex/notes.md")).json()[
            "decision"
        ]
        == "deny"
    )
    assert (
        action(
            client,
            hook,
            PATCH.replace(
                "*** End Patch", "*** Add File: extra.md\n+extra\n*** End Patch"
            ),
        ).json()["decision"]
        == "review"
    )
    assert client.get(route, headers=operator).json()["entries"] == []
    action(client, hook)
    row = client.get(route, headers=operator).json()["entries"][0]
    assert (
        client.post(f"{route}/{row['id']}/approve", headers=operator).status_code == 200
    )

    assert (
        action(client, hook, PATCH.replace("+after", "+something else")).json()[
            "decision"
        ]
        == "review"
    )
    notes.write_text("changed in the meantime\n", encoding="utf-8")
    assert action(client, hook).json()["decision"] == "review"
    notes.write_text("before\n", encoding="utf-8")
    now[0] += testing_approvals.APPROVAL_SECONDS
    retried = action(client, hook).json()
    assert retried["decision"] == "review"
    replacement = client.get(route, headers=operator).json()["entries"]
    pending = next(r for r in replacement if r["id"] in retried["reason"])
    assert pending["id"] != row["id"]
    assert (
        client.post(f"{route}/{pending['id']}/decline", headers=operator).json()[
            "status"
        ]
        == "declined"
    )
    assert action(client, hook).json()["decision"] == "deny"


@pytest.mark.parametrize("provider", ["codex", "claude"])
def test_installer_scopes_prompt_and_tool_hooks(tmp_path: Path, provider):
    target = install_hook(
        tmp_path, provider, 8010, tool_guard=True, test_scope=tmp_path / "scope.json"
    )
    config = json.loads(target.read_text(encoding="utf-8"))
    for event in ("UserPromptSubmit", "PreToolUse"):
        definition = config["hooks"][event][0]["hooks"][0]
        assert "--test-scope" in definition["command"]
        assert "statusMessage" not in definition
