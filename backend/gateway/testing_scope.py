"""Shared, dependency-free configuration for the single Codex test session."""

import json
from pathlib import Path
from typing import NamedTuple
from uuid import UUID

SCOPE_PATH = Path(__file__).resolve().parents[2] / ".uv-cache" / "approval-testing.json"


class TestingScope(NamedTuple):
    session: str
    hook_key: str


def read_scope(path: Path) -> TestingScope | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        key = data["hook_key"]
        if not isinstance(key, str) or len(key) != 43 or not key.isascii():
            return None
        return TestingScope(str(UUID(data["session"])), key)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def operator_path(scope_path: Path) -> Path:
    return scope_path.with_suffix(".operator.key")
