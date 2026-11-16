import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.eval import codex_smoke


def test_desktop_discovery_uses_registered_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    incomplete = tmp_path / "incomplete"
    package = tmp_path / "OpenAI Codex"
    bundled = package / "app/resources/codex.exe"
    bundled.parent.mkdir(parents=True)
    bundled.touch()

    def query(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
        assert "Get-AppxPackage -Name 'OpenAI.Codex'" in args[4]
        return subprocess.CompletedProcess(args, 0, f"{incomplete}\n\n{package}\n")

    monkeypatch.setattr(subprocess, "run", query)
    assert codex_smoke.desktop_codex() == str(bundled)


def test_cli_on_path_skips_desktop_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex_smoke.shutil, "which", lambda _: "codex-from-path")

    def unexpected_lookup() -> None:
        pytest.fail("Desktop discovery ran even though Codex was on PATH.")

    monkeypatch.setattr(codex_smoke, "desktop_codex", unexpected_lookup)
    assert codex_smoke.find_codex() == "codex-from-path"
