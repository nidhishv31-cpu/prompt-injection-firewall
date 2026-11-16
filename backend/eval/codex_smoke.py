"""Exercise a real Codex CLI session with a deterministic loopback model."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile
from threading import Thread
from time import monotonic, sleep, time
from typing import Any
from unittest.mock import patch

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response

from backend.config import ROOT
from backend.gateway.responses import WITHHELD_DOCUMENT
from backend.main import app as firewall
from backend.pipeline.retrieval import CLEAN, FLAGGED
from backend.victim_app.documents import DOCUMENT_EVENT_MARKER

FINISHED = "Local Codex firewall smoke test completed."
DEFAULT_PROMPT = "What are the store hours?"


@contextmanager
def serve(app: FastAPI) -> Iterator[str]:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", ws="none"))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = monotonic() + 15
            while not server.started:
                if not thread.is_alive() or monotonic() > deadline:
                    raise RuntimeError("A local smoke-test server did not start.")
                sleep(0.05)
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=10)


def tool_calls(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for tool in tools:
        name = tool.get("name")
        namespace = {}
        if tool.get("type") == "namespace" and name == "mcp__firewall_notes":
            if not any(
                child.get("name") == "read_note" for child in tool.get("tools", [])
            ):
                continue
            namespace = {"namespace": name}
            name = "read_note"
        elif name != "mcp__firewall_notes__read_note":
            continue
        return [
            {
                "type": "function_call",
                "id": f"fc_smoke_{label}",
                "call_id": f"call_smoke_{label}",
                "name": name,
                "arguments": json.dumps({"note": label}),
                "status": "completed",
                **namespace,
            }
            for label in ("clean", "flagged")
        ]
    names = ", ".join(str(tool.get("name", tool.get("type"))) for tool in tools)
    raise RuntimeError(
        f"Codex did not advertise the fixture lookup tool. It advertised: {names}."
    )


def model_response(
    number: int, model: str, items: list[dict[str, Any]], stream: bool
) -> Response:
    base = {
        "object": "response",
        "id": f"resp_smoke_{number}",
        "created_at": int(time()),
        "model": model,
        "error": None,
        "incomplete_details": None,
    }
    usage = {
        "input_tokens": 8,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": 8,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": 16,
    }
    final = {**base, "status": "completed", "output": items, "usage": usage}
    if not stream:
        return JSONResponse(final)
    in_progress = {**base, "status": "in_progress", "output": [], "usage": None}
    events: list[tuple[str, dict[str, Any]]] = [
        ("response.created", {"response": in_progress}),
        ("response.in_progress", {"response": in_progress}),
    ]
    for index, item in enumerate(items):
        opening_item = {**item, "status": "in_progress"}
        if item["type"] == "message":
            opening_item["content"] = []
        else:
            opening_item["arguments"] = ""
        events.append(
            (
                "response.output_item.added",
                {"output_index": index, "item": opening_item},
            )
        )
        if item["type"] == "message":
            part = item["content"][0]
            location = {
                "item_id": item["id"],
                "output_index": index,
                "content_index": 0,
            }
            events.extend(
                [
                    (
                        "response.content_part.added",
                        {**location, "part": {**part, "text": ""}},
                    ),
                    ("response.output_text.delta", {**location, "delta": part["text"]}),
                    ("response.output_text.done", {**location, "text": part["text"]}),
                    ("response.content_part.done", {**location, "part": part}),
                ]
            )
        else:
            events.append(
                (
                    "response.function_call_arguments.done",
                    {
                        "item_id": item["id"],
                        "output_index": index,
                        "arguments": item["arguments"],
                    },
                )
            )
        events.append(
            ("response.output_item.done", {"output_index": index, "item": item})
        )
    events.append(("response.completed", {"response": final}))
    wire = "".join(
        f"event: {kind}\ndata: "
        + json.dumps({"type": kind, "sequence_number": index, **data})
        + "\n\n"
        for index, (kind, data) in enumerate(events)
    )
    return Response(wire, media_type="text/event-stream")


def mock_model(requests: list[dict[str, Any]]) -> FastAPI:
    mock = FastAPI()

    @mock.post("/v1/responses")
    def create(payload: dict[str, Any]) -> Response:
        requests.append(payload)
        items = payload.get("input", [])
        reported = any(
            isinstance(item, dict)
            and item.get("type") == "function_call_output"
            and str(item.get("call_id", "")).startswith("call_smoke_")
            for item in items
            if isinstance(items, list)
        )
        if reported:
            output = [
                {
                    "type": "message",
                    "id": "msg_smoke_finished",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {"type": "output_text", "text": FINISHED, "annotations": []}
                    ],
                }
            ]
        else:
            output = tool_calls(payload.get("tools", []))
        return model_response(
            len(requests), payload["model"], output, payload.get("stream") is True
        )

    return mock


def run_codex(
    command: list[str],
    prompt: str,
    environment: dict[str, str],
    workspace: Path,
    prompt_blocked: Callable[[], bool] | None,
) -> subprocess.CompletedProcess[str]:
    # File-backed streams let the test finish if a Codex subprocess retains a
    # standard stream handle after a policy rejection on Windows.
    with TemporaryFile() as stdin, TemporaryFile() as stdout, TemporaryFile() as stderr:
        stdin.write(prompt.encode("utf-8"))
        stdin.seek(0)
        with subprocess.Popen(
            command,
            env=environment,
            cwd=workspace,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        ) as process:
            deadline = monotonic() + 90
            while process.poll() is None:
                if prompt_blocked and prompt_blocked():
                    process.terminate()
                    break
                if monotonic() >= deadline:
                    process.kill()
                    raise subprocess.TimeoutExpired(command, 90)
                sleep(0.1)
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout.read().decode("utf-8", errors="replace"),
            stderr.read().decode("utf-8", errors="replace"),
        )


def run_smoke(codex: str, directory: Path, prompt: str | None = None) -> None:
    home = directory / "codex-home"
    workspace = directory / "fixtures"
    home.mkdir()
    workspace.mkdir()
    requests: list[dict[str, Any]] = []
    with (
        serve(mock_model(requests)) as upstream,
        patch.dict(
            os.environ,
            {
                "PI_FIREWALL_RESPONSES_UPSTREAM": upstream,
                "PI_FIREWALL_DB": str(directory / "audit.sqlite3"),
                "PI_FIREWALL_EMBEDDING_MODEL": "",
                "PI_FIREWALL_NOTES_DIR": "",
                "PYTHON_DOTENV_DISABLED": "1",
            },
        ),
        serve(firewall) as gateway,
    ):
        (home / "config.toml").write_text(
            'model_provider = "firewall_smoke"\n'
            'model = "gpt-5.4"\n'
            'approval_policy = "never"\n'
            "[analytics]\nenabled = false\n"
            "[model_providers.firewall_smoke]\n"
            'name = "Local firewall smoke test"\n'
            f'base_url = "{gateway}/v1"\n'
            'wire_api = "responses"\n'
            "requires_openai_auth = false\n"
            "supports_websockets = false\n"
            "request_max_retries = 0\n"
            "stream_max_retries = 0\n"
            "[mcp_servers.firewall_notes]\n"
            f"command = {json.dumps(sys.executable)}\n"
            f'args = ["-m", "backend.gateway.rag_mcp", "--port", "{gateway.rsplit(":", 1)[1]}"]\n'
            f"cwd = {json.dumps(str(ROOT.parent))}\n"
            'enabled_tools = ["read_note"]\n'
            'default_tools_approval_mode = "writes"\n'
            "required = true\n",
            encoding="utf-8",
        )
        child = {
            **os.environ,
            "CODEX_HOME": str(home),
            "NO_PROXY": "127.0.0.1,localhost",
        }
        store = firewall.state.store

        def prompt_blocked() -> bool:
            return not requests and any(
                row.decision == "block"
                and any(
                    reason.get("layer") == "responses"
                    and reason.get("evidence") == "firewall_blocked"
                    for reason in row.reasons
                )
                for row in store.recent()
            )

        result = run_codex(
            [
                codex,
                "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "--color",
                "never",
                "-",
            ],
            DEFAULT_PROMPT if prompt is None else prompt,
            child,
            workspace,
            prompt_blocked if prompt is not None else None,
        )
        audit = list(reversed(store.recent()))
        decisions = [
            row.decision for row in audit if row.original == "[Responses API request]"
        ]
        if prompt is not None and prompt_blocked():
            print("Prompt decision: block. The mock upstream received no request.")
            return
        if result.returncode or FINISHED not in result.stdout:
            raise RuntimeError(
                f"Codex did not complete the mock turn.\n{result.stderr}\n{result.stdout}"
            )
        if len(requests) != 2:
            raise RuntimeError(
                f"Expected two upstream requests, received {len(requests)}."
            )
        forwarded = json.dumps(requests[-1]["input"])
        if CLEAN not in forwarded or WITHHELD_DOCUMENT not in forwarded:
            outputs = {
                item["call_id"]: str(item.get("output"))[:500]
                for item in requests[-1]["input"]
                if isinstance(item, dict)
                and item.get("call_id") in {"call_smoke_clean", "call_smoke_flagged"}
                and item.get("type") == "function_call_output"
            }
            raise RuntimeError(
                f"The two fixture results did not arrive as expected: {outputs}"
            )
        if FLAGGED in forwarded or DOCUMENT_EVENT_MARKER in forwarded:
            raise RuntimeError("The upstream received the withheld fixture.")
        if sorted(
            row.decision for row in audit if row.original == "[Guarded note retrieval]"
        ) != ["allow", "sanitize"]:
            raise RuntimeError(
                "The guarded retrieval server did not inspect both notes."
            )
        normal_decisions = (
            ("allow",) if prompt is None else ("allow", "flag", "sanitize")
        )
        if (
            len(decisions) != 2
            or decisions[0] not in normal_decisions
            or decisions[1] not in normal_decisions
        ):
            raise RuntimeError(
                f"The gateway audit did not record the expected decisions: {decisions}."
            )
    print(
        f"Codex routed two requests automatically. The prompt decision was {decisions[0]}."
    )
    print(
        "The mock upstream received the clean result and the placeholder for the withheld result."
    )


def desktop_codex() -> str | None:
    powershell = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); "
        "Get-AppxPackage -Name 'OpenAI.Codex' | Sort-Object Version -Descending "
        "| Select-Object -ExpandProperty InstallLocation"
    )
    try:
        packages = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for location in packages.stdout.splitlines():
        root = Path(location.strip())
        candidate = root / "app/resources/codex.exe"
        try:
            if root.is_absolute() and candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def find_codex() -> str | None:
    executable = shutil.which("codex")
    if executable or sys.platform != "win32":
        return executable
    return desktop_codex()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--codex",
        help="Path to the Codex CLI executable. Defaults to PATH or the Windows desktop installation.",
    )
    parser.add_argument(
        "--prompt", help="Send your own prompt through the isolated Codex session."
    )
    args = parser.parse_args()
    if args.prompt is not None and not args.prompt.strip():
        parser.error("--prompt must contain some text.")
    codex = args.codex or find_codex()
    if not codex:
        parser.error(
            "Could not find Codex on PATH or in the Windows desktop installation. "
            "Pass the executable path with --codex or install the Codex CLI."
        )
    scratch = ROOT.parent / ".uv-cache"
    scratch.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="codex-smoke-", dir=scratch) as directory:
        run_smoke(codex, Path(directory), args.prompt)


if __name__ == "__main__":
    main()
