"""Bridge a desktop coding client's submitted-prompt hook to the local firewall."""

import argparse
import json
import sys
from http.client import HTTPException
from typing import Any

if __package__:
    from .local_http import request_json
else:
    from local_http import request_json

MAX_HOOK_INPUT = 256 * 1024
DENIED = "Prompt Firewall stopped this message because its decision was"
UNAVAILABLE = "Prompt Firewall could not check this message. Start the local firewall on port {port}."


def inspect_prompt(app: str, port: int, prompt: str) -> str:
    verdict = request_json(
        port, "POST", "/api/inspect-prompt", {"source": app, "text": prompt}
    )
    decision = verdict.get("decision") if isinstance(verdict, dict) else None
    if decision not in ("allow", "flag", "sanitize", "block"):
        raise ValueError("The firewall returned an invalid verdict.")
    return decision


def hook_reply(app: str, port: int, raw: bytes) -> dict[str, Any]:
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
        decision = inspect_prompt(app, port, prompt)
    except (OSError, HTTPException, TypeError, ValueError, RecursionError):
        return {"decision": "block", "reason": UNAVAILABLE.format(port=port)}
    if decision in ("sanitize", "block"):
        return {"decision": "block", "reason": f"{DENIED} {decision}."}
    return {}


def action_reply(app: str, port: int, raw: bytes) -> dict[str, Any]:
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("codex", "claude"), required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--event", choices=("prompt", "tool"), default="prompt")
    args = parser.parse_args()
    handler = hook_reply if args.event == "prompt" else action_reply
    print(
        json.dumps(
            handler(args.app, args.port, sys.stdin.buffer.read(MAX_HOOK_INPUT + 1))
        )
    )


if __name__ == "__main__":
    main()
