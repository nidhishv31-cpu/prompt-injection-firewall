"""Short-lived approvals for one-file documentation edits in a Codex test chat."""

import json
import re
from dataclasses import dataclass, replace
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from secrets import token_urlsafe
from threading import Lock
from time import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response

from backend.gateway.testing_scope import TestingScope, operator_path, read_scope
from backend.models import ActionRequest
from backend.pipeline.action_policy import ActionResult, safe_path
from backend.pipeline.policy import Decision, Reason

MAX_PATCH = 16 * 1024
MAX_FILE = 128 * 1024
QUEUE_LIMIT = 20
REVIEW_SECONDS = 600
APPROVAL_SECONDS = 120
FILE_HEADER = re.compile(r"\*\*\* (Add|Update) File: ([A-Za-z0-9_. /-]+)")
RESERVED_NAME = re.compile(r"(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])", re.IGNORECASE)
router = APIRouter(prefix="/api/testing-approvals")


@dataclass(frozen=True)
class Entry:
    id: str
    path: str
    patch: str
    status: Literal["pending", "approved", "consumed", "declined", "expired"]
    expires_at: float


def eligible_patch(
    root: Path, protected_roots: tuple[Path, ...], body: ActionRequest
) -> tuple[str, str, str] | None:
    if body.tool != "apply_patch" or set(body.arguments) != {"command"}:
        return None
    patch = body.arguments["command"]
    if not isinstance(patch, str) or len(patch) > MAX_PATCH:
        return None
    try:
        encoded = patch.encode("utf-8")
    except UnicodeError:
        return None
    if len(encoded) > MAX_PATCH or any(
        not char.isprintable() and char not in "\r\n\t" for char in patch
    ):
        return None
    lines = patch.replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) < 4 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        return None
    match = FILE_HEADER.fullmatch(lines[1])
    if not match:
        return None
    operation, name = match.groups()
    if any(
        not part
        or part.endswith((" ", "."))
        or RESERVED_NAME.fullmatch(part.split(".")[0])
        for part in name.split("/")
    ):
        return None
    working = root / body.cwd
    if not safe_path(root, working, name, protected_roots):
        return None
    path = working / name
    if path.suffix.lower() not in {".md", ".txt"}:
        return None
    changes = lines[2:-1]
    if operation == "Add":
        if any(not line.startswith("+") for line in changes):
            return None
    elif not all(
        line.startswith(("+", "-", " ", "@@ ")) or line in {"@@", "*** End of File"}
        for line in changes
    ) or not any(line.startswith(("+", "-")) for line in changes):
        return None
    try:
        if path != path.resolve() or not path.parent.is_dir():
            return None
        if operation == "Add":
            if path.exists():
                return None
            baseline = "absent"
        else:
            if not path.is_file():
                return None
            with path.open("rb") as source:
                content = source.read(MAX_FILE + 1)
            if len(content) > MAX_FILE:
                return None
            content.decode("utf-8")
            baseline = sha256(content).hexdigest()
        relative = path.relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None
    key = sha256(
        json.dumps([str(working), relative, baseline, patch]).encode()
    ).hexdigest()
    return key, relative, patch


class ApprovalQueue:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = Lock()
        self.scope: TestingScope | None = None
        self.entries: dict[str, Entry] = {}

    def _current(self) -> TestingScope | None:
        scope = read_scope(self.path)
        if self.scope != scope:
            self.entries.clear()
            self.scope = scope
        return scope

    def _expire(self, now: float) -> None:
        for key, row in list(self.entries.items()):
            if now >= row.expires_at + REVIEW_SECONDS:
                del self.entries[key]
            elif now >= row.expires_at and row.status in {"pending", "approved"}:
                self.entries[key] = replace(row, patch="", status="expired")

    def _matches(self, request: Request, provider: str) -> bool:
        scope = self._current()
        return bool(
            scope
            and provider == "codex"
            and request.headers.get("x-firewall-session") == scope.session
            and compare_digest(
                request.headers.get("x-firewall-hook-key", "").encode(),
                scope.hook_key.encode(),
            )
        )

    def verify_hook(self, request: Request, provider: str) -> None:
        with self.lock:
            if not self._matches(request, provider):
                raise HTTPException(
                    403, "The testing hook is outside the selected session."
                )

    def inspect(
        self,
        request: Request,
        body: ActionRequest,
        result: ActionResult,
    ) -> ActionResult:
        state = request.app.state
        with self.lock:
            if not self._matches(request, body.source):
                raise HTTPException(
                    403, "The testing hook is outside the selected session."
                )
            if result.decision != "review":
                return result
            candidate = eligible_patch(state.action_root, state.protected_roots, body)
            if candidate is None:
                return result
            key, path, patch = candidate
            now = time()
            self._expire(now)
            row = self.entries.get(key)
            if row and row.status == "approved":
                self.entries[key] = replace(row, patch="", status="consumed")
                return ActionResult(
                    decision="allow",
                    reason=f"Testing approval {row.id} consumed. Native permissions apply.",
                )
            if row and row.status == "declined":
                return ActionResult(
                    decision="deny", reason=f"Testing approval {row.id} was declined."
                )
            if row and row.status == "consumed":
                return ActionResult(
                    decision="deny",
                    reason=f"Testing approval {row.id} was already used.",
                )
            if row is None or row.status == "expired":
                if row is None and len(self.entries) >= QUEUE_LIMIT:
                    return ActionResult(
                        decision="review", reason="The testing approval queue is full."
                    )
                row = Entry(
                    token_urlsafe(12), path, patch, "pending", now + REVIEW_SECONDS
                )
                self.entries.pop(key, None)
                self.entries[key] = row
            return ActionResult(
                decision="review",
                reason=f"Testing approval {row.id} is pending in Dashboard. Wait for approval and retry the exact patch.",
            )

    def _operator(self, request: Request) -> TestingScope | None:
        try:
            key = operator_path(self.path).read_text(encoding="utf-8").strip()
        except OSError:
            key = ""
        if len(key) != 43 or not compare_digest(
            request.headers.get("authorization", "").encode(),
            f"Bearer {key}".encode(),
        ):
            raise HTTPException(401, "Enter the local approval key.")
        return self._current()

    def list(self, request: Request) -> dict[str, object]:
        with self.lock:
            scope = self._operator(request)
            self._expire(time())
            return {
                "session": scope.session if scope else None,
                "entries": list(reversed(self.entries.values())),
            }

    def decide(
        self, request: Request, identifier: str, choice: Literal["approve", "decline"]
    ) -> Entry:
        with self.lock:
            self._operator(request)
            now = time()
            self._expire(now)
            for key, row in self.entries.items():
                if row.id == identifier:
                    if row.status != "pending":
                        raise HTTPException(409, "This request is no longer pending.")
                    updated = (
                        replace(
                            row, status="approved", expires_at=now + APPROVAL_SECONDS
                        )
                        if choice == "approve"
                        else replace(row, status="declined", patch="")
                    )
                    request.app.state.store.record(
                        original="[Codex testing approval]",
                        normalized="",
                        decision=(
                            Decision.FLAG if choice == "approve" else Decision.BLOCK
                        ),
                        risk=0.5 if choice == "approve" else 1.0,
                        reasons=[
                            Reason(
                                layer="tool_policy",
                                score=0.5 if choice == "approve" else 1.0,
                                evidence=f"Testing approval {row.id} {updated.status}.",
                                category="tool_policy",
                            )
                        ],
                        latency_ms=0,
                    )
                    self.entries[key] = updated
                    return updated
            raise HTTPException(404, "Testing approval not found.")


@router.get("")
def approvals(request: Request, response: Response) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    return request.app.state.approvals.list(request)


@router.post("/{identifier}/{choice}")
def decide_approval(
    request: Request,
    response: Response,
    identifier: str,
    choice: Literal["approve", "decline"],
) -> Entry:
    response.headers["Cache-Control"] = "no-store"
    return request.app.state.approvals.decide(request, identifier, choice)
