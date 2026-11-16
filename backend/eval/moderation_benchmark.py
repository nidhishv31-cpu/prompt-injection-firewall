"""Measure moderation and the Windows chat-hook path against local fixtures."""

import argparse
import asyncio
import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from statistics import median, quantiles
from tempfile import TemporaryDirectory
from time import perf_counter
from typing import Any
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from backend.config import ModerationMode, Settings
from backend.eval.codex_smoke import serve
from backend.main import app
from backend.setup_chat_hooks import SCRIPT, hook_arguments

CORPUS = Path(__file__).with_name("moderation.jsonl")


def percentiles(samples: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(median(samples), 2),
        "p95_ms": round(quantiles(samples, n=100, method="inclusive")[94], 2),
    }


def mock_stream() -> FastAPI:
    mock = FastAPI()

    @mock.post("/v1/responses")
    def stream() -> StreamingResponse:
        async def events() -> AsyncIterator[str]:
            for event in (
                {
                    "type": "response.output_text.delta",
                    "delta": "The store opens at ten.",
                },
                {
                    "type": "response.completed",
                    "response": {"object": "response", "output": []},
                },
            ):
                yield f"data: {json.dumps(event)}\n\n"
                await asyncio.sleep(0.02)

        return StreamingResponse(events(), media_type="text/event-stream")

    return mock


def moderation_samples(
    client: httpx.Client, port: int, original: Settings, fixtures: list[dict[str, Any]]
) -> dict[str, Any]:
    summaries = {}
    benign = sum(row["benign"] for row in fixtures)
    for mode in (
        ModerationMode.STRICT,
        ModerationMode.CONTEXTUAL,
        ModerationMode.REPORT_ONLY,
    ):
        app.state.settings = original.model_copy(
            update={"moderation": original.moderation.model_copy(update={"mode": mode})}
        )
        would_match = "strict" if mode == ModerationMode.REPORT_ONLY else mode.value
        expected = "reported" if mode == ModerationMode.REPORT_ONLY else "blocked"
        missed, unexpected, benign_holds, end_to_end = [], [], [], []
        matched, held = 0, 0
        for row in fixtures:
            data = {"source": "codex", "text": row["text"]}
            verdict = (
                client.post("/api/inspect-prompt", json=data).raise_for_status().json()
            )
            hit = verdict["moderation"] == expected
            matched += hit
            is_block = verdict["moderation"] == "blocked"
            held += is_block
            if row[would_match] and not hit:
                missed.append(row["id"])
            if hit and not row[would_match]:
                unexpected.append(row["id"])
            if row["benign"] and is_block:
                benign_holds.append(row["id"])
            if mode == ModerationMode.STRICT:
                packet = json.dumps(
                    {"hook_event_name": "UserPromptSubmit", "prompt": row["text"]}
                ).encode()
                start = perf_counter()
                output = subprocess.check_output(
                    hook_arguments("codex", port), input=packet, timeout=15
                )
                end_to_end.append((perf_counter() - start) * 1000)
                assert (json.loads(output).get("decision") == "block") == (
                    verdict["decision"] in ("block", "sanitize")
                )
        result = {
            "cases": len(fixtures),
            "matched": matched,
            "moderation_blocks": held,
            "benign_count": benign,
            "benign_block_rate": len(benign_holds) / benign,
            "benign_holds": benign_holds,
            "missed_policy_expectations": missed,
            "unexpected_policy_matches": unexpected,
        }
        if end_to_end:
            result["hook_subprocess"] = percentiles(end_to_end)
        summaries[mode.value] = result
    return summaries


def performance_samples(client: httpx.Client, original: Settings) -> dict[str, Any]:
    prompts = (
        "What are the store hours?",
        "Please summarize the terms of the store pickup policy.",
        "Which documentation covers the shipping estimate?",
    )
    http_stats = {}
    for name, size in (("uncached", 0), ("repeated", 256)):
        app.state.settings = original.model_copy(update={"inspection_cache_size": size})
        for text in prompts:
            client.post(
                "/api/inspect-prompt", json={"source": "codex", "text": text}
            ).raise_for_status()
        times = []
        for i in range(18):
            start = perf_counter()
            client.post(
                "/api/inspect-prompt",
                json={"source": "codex", "text": prompts[i % len(prompts)]},
            ).raise_for_status()
            times.append((perf_counter() - start) * 1000)
        http_stats[name] = percentiles(times)
    port = client.base_url.port
    if port is None:
        raise ValueError("The benchmark requires a loopback port.")
    launchers = {
        "previous_launcher": [
            sys.executable,
            str(SCRIPT),
            "--app",
            "codex",
            "--port",
            str(port),
        ],
        "stdlib_launcher": hook_arguments("codex", port),
    }
    launches: dict[str, list[float]] = {name: [] for name in launchers}
    for i in range(12):
        packet = json.dumps(
            {"hook_event_name": "UserPromptSubmit", "prompt": prompts[i % len(prompts)]}
        ).encode()
        order = list(launchers) if i % 2 == 0 else list(reversed(launchers))
        for name in order:
            start = perf_counter()
            result = subprocess.check_output(launchers[name], input=packet, timeout=15)
            launches[name].append((perf_counter() - start) * 1000)
            assert json.loads(result) == {}
    upstream_first, client_first, total = [], [], []
    for _ in range(10):
        start = perf_counter()
        with client.stream(
            "POST",
            "/v1/responses",
            json={
                "model": "local-timing-fixture",
                "input": prompts[0],
                "stream": True,
            },
        ) as response:
            response.raise_for_status()
            units = {
                part.split(";dur=")[0]: float(part.split(";dur=")[1])
                for part in response.headers["Server-Timing"].split(", ")
            }
            chunks = response.iter_raw()
            next(chunks)
            client_first.append((perf_counter() - start) * 1000)
            for _ in chunks:
                pass
        upstream_first.append(units["upstream-first-body-byte"])
        total.append((perf_counter() - start) * 1000)
    return {
        "prompt_http": http_stats,
        "hook_launcher": {
            name: percentiles(samples) for name, samples in launches.items()
        },
        "gateway_stream_local_mock": {
            "upstream_first_body_byte": percentiles(upstream_first),
            "client_first_body_byte": percentiles(client_first),
            "client_total": percentiles(total),
        },
    }


def run() -> dict[str, Any]:
    fixtures = [
        json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()
    ]
    with TemporaryDirectory() as directory, serve(mock_stream()) as upstream:
        test_env = {
            "PI_FIREWALL_DB": str(Path(directory) / "moderation.sqlite3"),
            "PI_FIREWALL_EMBEDDING_MODEL": "",
            "PI_FIREWALL_NOTES_DIR": "",
            "PI_FIREWALL_RESPONSES_UPSTREAM": upstream,
            "PYTHON_DOTENV_DISABLED": "1",
        }
        with (
            patch.dict(os.environ, test_env),
            serve(app) as gateway,
            httpx.Client(base_url=gateway, trust_env=False) as client,
        ):
            original = app.state.settings
            modes = moderation_samples(
                client, int(gateway.rsplit(":", 1)[1]), original, fixtures
            )
            performance = performance_samples(client, original)
    return {"moderation": modes, "performance": performance}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    summary = run()
    text = json.dumps(summary, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8", newline="\n")
    print(text)
    if any(
        mode["missed_policy_expectations"] or mode["unexpected_policy_matches"]
        for mode in summary["moderation"].values()
    ):
        raise SystemExit(
            "Moderation decisions differed from the fixed policy expectations."
        )


if __name__ == "__main__":
    main()
