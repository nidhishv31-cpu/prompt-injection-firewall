"""Bridge a desktop coding client's submitted-prompt hook to the local firewall."""

import argparse
import json
import sys
from http.client import HTTPException
from pathlib import Path
from typing import Any

if __package__:
    from .local_http import request_json
    from .testing_scope import SCOPE_PATH, read_scope
else:
    from local_http import request_json
    from testing_scope import SCOPE_PATH, read_scope

MAX_HOOK_INPUT = 256 * 1024
DENIED = "Prompt Firewall stopped this message because its decision was"
UNAVAILABLE = "Prompt Firewall could not check this message. Start the local firewall on port {port}."


def inspect_prompt(app: str, port: int, prompt: str, **options: Any) -> tuple[str, str]:
    verdict = request_json(
        port, "POST", "/api/inspect-prompt", {"source": app, "text": prompt}, **options
    )
    decision = verdict.get("decision") if isinstance(verdict, dict) else None
    if decision not in ("allow", "flag", "sanitize", "block"):
        raise ValueError("The firewall returned an invalid verdict.")
    moderation = verdict.get("moderation", "clear")
    if moderation not in ("clear", "reported", "blocked"):
        raise ValueError("The firewall returned an invalid moderation verdict.")
    return decision, moderation


def hook_reply(app: str, port: int, raw: bytes, **options: Any) -> dict[str, Any]:
    try:
        if len(raw) > MAX_HOOK_INPUT:
            return {
                "decision": "block",
                "reason": "Prompt Firewall could not check this message because it is too large.",
            }
        event = json.loads(raw)
        if (
            not isinstance(event, dict)
            or event.get("hook_event_name") != "UserPromptSubmit"
        ):
            raise ValueError("Unexpected hook event.")
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            raise TypeError("The hook did not provide prompt text.")
        decision, moderation = inspect_prompt(app, port, prompt, **options)
    except (OSError, HTTPException, TypeError, ValueError, RecursionError):
        return {"decision": "block", "reason": UNAVAILABLE.format(port=port)}
    if moderation == "blocked":
        return {
            "decision": "block",
            "reason": "Prompt Firewall blocked vulgar language under the local moderation policy.",
        }
    if decision in ("sanitize", "block"):
        return {"decision": "block", "reason": f"{DENIED} {decision}."}
    return {}


def action_reply(app: str, port: int, raw: bytes, **options: Any) -> dict[str, Any]:
    try:
        if len(raw) > MAX_HOOK_INPUT:
            raise ValueError("Tool event exceeds the inspection limit.")
        event = json.loads(raw)
        if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
            raise ValueError("Unexpected tool event.")
        verdict = request_json(
            port,
            "POST",
            "/api/inspect-action",
            {
                "source": app,
                "cwd": event.get("cwd", ""),
                "tool": event["tool_name"],
                "arguments": event["tool_input"],
            },
            **options,
        )
        decision, reason = verdict["decision"], verdict["reason"]
        if decision not in ("allow", "review", "deny") or not isinstance(reason, str):
            raise ValueError("Invalid tool verdict.")
    except (OSError, HTTPException, KeyError, TypeError, ValueError, RecursionError):
        decision, reason = (
            "deny",
            f"Prompt Firewall could not check this action on port {port}.",
        )
    if decision == "allow":
        return {}
    if decision == "review" and app == "codex":
        reason += " This Codex hook holds the action for manual review."
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": (
                "ask" if decision == "review" and app == "claude" else "deny"
            ),
            "permissionDecisionReason": reason,
        }
    }


def dispatch(
    app: str, port: int, kind: str, raw: bytes, scope_path: Path | None
) -> dict[str, Any]:
    handler = hook_reply if kind == "prompt" else action_reply
    if scope_path is None:
        return handler(app, port, raw)
    if app != "codex":
        return {}
    scope = read_scope(scope_path)
    if scope is None:
        return {}
    try:
        event = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    if not isinstance(event, dict) or event.get("session_id") != scope.session:
        return {}
    return handler(
        app,
        port,
        raw,
        headers={
            "X-Firewall-Session": scope.session,
            "X-Firewall-Hook-Key": scope.hook_key,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("codex", "claude"), required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--event", choices=("prompt", "tool"), default="prompt")
    parser.add_argument("--test-scope", type=Path)
    args = parser.parse_args()
    scope_path = args.test_scope
    # Hooks loaded from an older project config still honor the local test switch.
    if scope_path is None and SCOPE_PATH.is_file():
        scope_path = SCOPE_PATH
    print(
        json.dumps(
            dispatch(
                args.app,
                args.port,
                args.event,
                sys.stdin.buffer.read(MAX_HOOK_INPUT + 1),
                scope_path,
            )
        )
    )


if __name__ == "__main__":
    main()
