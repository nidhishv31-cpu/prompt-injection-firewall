"""Decide whether supported native tool calls can reach the client's permission layer."""

import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel

READ_TOOLS = {"Read", "LS"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell", "shell_command", "exec_command"}
SEARCH_TOOLS = {"Glob", "Grep", "WebSearch"}
GUARDED_TOOLS = {"mcp__firewall_notes__read_note", "mcp__firewall_notes__list_notes"}
_PROTECTED = {
    ".git",
    ".codex",
    ".claude",
    ".aws",
    ".ssh",
    ".uv-cache",
    ".venv",
    ".env",
    "credentials",
    "auth.json",
    "id_rsa",
    "id_ed25519",
}
_NETWORK = {
    "curl",
    "curl.exe",
    "wget",
    "invoke-webrequest",
    "invoke-restmethod",
    "ssh",
    "scp",
}
_PATCH_FILE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$", re.MULTILINE
)
_SHELL_READ = re.compile(
    r"""(?:get-content +-literalpath|cat) +(?:'([^'\r\n]+)'|"([^"\r\n]+)"|([^\s]+))\Z""",
    re.IGNORECASE,
)
_NON_LITERAL = frozenset("\r\n\t;|&<>$%*?[]\x00" + chr(96))


class ActionResult(BaseModel):
    decision: Literal["allow", "deny", "review"]
    reason: str


def safe_path(
    root: Path, cwd: Path, name: object, protected_roots: tuple[Path, ...] = ()
) -> bool:
    if not isinstance(name, str) or not name or name.startswith(("//", "\\\\")):
        return False
    if any(char in name for char in _NON_LITERAL):
        return False
    candidate = cwd / name
    if any(_protected(part) for part in candidate.parts if part != candidate.anchor):
        return False
    try:
        resolved = candidate.resolve()
        inside = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return not any(_protected(part) for part in inside.parts) and not any(
        resolved.is_relative_to(protected) for protected in protected_roots
    )


def _protected(part: str) -> bool:
    normalized = part.rstrip(" .").casefold()
    return (
        ":" in part
        or normalized in _PROTECTED
        or normalized.startswith(".env.")
        or normalized.endswith(
            (".pem", ".key", ".pfx", ".db", ".sqlite", ".sqlite3", ".joblib")
        )
    )


def evaluate_action(
    root: Path,
    cwd: str,
    tool: str,
    arguments: dict[str, Any],
    allowed_domains: tuple[str, ...] = (),
    protected_roots: tuple[Path, ...] = (),
) -> ActionResult:
    allow = ActionResult(
        decision="allow", reason="The action may proceed to native permissions."
    )
    deny_path = ActionResult(
        decision="deny",
        reason="The action targets a protected or out-of-workspace path.",
    )
    review = ActionResult(
        decision="review", reason="This action requires explicit human approval."
    )
    root = root.resolve()
    working = root / cwd if cwd else root
    if not safe_path(root, root, str(working), protected_roots):
        return deny_path
    if tool in GUARDED_TOOLS:
        return allow
    if tool in READ_TOOLS | WRITE_TOOLS:
        path = arguments.get("file_path", arguments.get("path"))
        if not safe_path(root, working, path, protected_roots):
            return deny_path
        return review if tool in WRITE_TOOLS else allow
    if tool in SEARCH_TOOLS:
        path = arguments.get("path")
        return (
            deny_path
            if path is not None and not safe_path(root, working, path, protected_roots)
            else review
        )
    if tool == "WebFetch":
        value = arguments.get("url")
        try:
            url = urlsplit(value) if isinstance(value, str) else None
            approved = (
                url is not None
                and url.scheme == "https"
                and url.hostname in allowed_domains
                and url.port in (None, 443)
                and not (url.query or url.username or url.password or url.fragment)
            )
        except ValueError:
            approved = False
        if approved:
            return review
        return ActionResult(
            decision="deny",
            reason="The destination is outside the approved HTTPS destinations.",
        )
    if tool == "apply_patch":
        patch = arguments.get("command", arguments.get("input"))
        if isinstance(patch, str) and any(
            not safe_path(root, working, path, protected_roots)
            for path in _PATCH_FILE.findall(patch)
        ):
            return deny_path
        return review
    if tool in SHELL_TOOLS:
        command = arguments.get("command", arguments.get("cmd"))
        workdir = arguments.get("workdir") or str(working)
        if not isinstance(workdir, str) or not safe_path(
            root, working, workdir, protected_roots
        ):
            return deny_path
        if not isinstance(command, str):
            return review
        command = command.strip()
        words = command.casefold().split(maxsplit=1)
        if words and words[0] in _NETWORK:
            return ActionResult(
                decision="deny",
                reason="Network commands are disabled in the protected shell.",
            )
        if command.casefold() in {"pwd", "get-location"}:
            return allow
        match = _SHELL_READ.fullmatch(command)
        if match:
            path = next(group for group in match.groups() if group is not None)
            return (
                allow
                if safe_path(root, working / workdir, path, protected_roots)
                else deny_path
            )
    return review
