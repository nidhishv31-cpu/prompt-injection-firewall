import json
from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from os import getenv
from time import perf_counter
from typing import Any

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from backend.config import Settings
from backend.db import Store
from backend.pipeline.doc_scanner import scan
from backend.pipeline.firewall import Firewall
from backend.pipeline.output_filter import inspect_output
from backend.pipeline.policy import Decision, Reason
from backend.victim_app.documents import Document

router = APIRouter()
MAX_BODY = 4 * 1024 * 1024
MAX_TEXT = 128 * 1024
WITHHELD_DOCUMENT = "[Tool result withheld by the prompt firewall.]"
WITHHELD_PROMPT = "[User text withheld by the prompt firewall.]"
TOOL_OUTPUT_TYPES = {"function_call_output", "custom_tool_call_output", "mcp_call"}
TOOL_ARGUMENT_FIELDS = {
    "function_call": "arguments",
    "custom_tool_call": "input",
    "mcp_call": "arguments",
    "shell_call": "action",
    "local_shell_call": "action",
}
ARGUMENT_EVENTS = {
    "response.function_call_arguments": "arguments",
    "response.custom_tool_call_input": "input",
    "response.mcp_call_arguments": "arguments",
}
DECISION_ORDER = {decision: rank for rank, decision in enumerate(Decision)}


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code

    def response(self) -> JSONResponse:
        return JSONResponse(
            {
                "error": {
                    "message": str(self),
                    "type": "gateway_error",
                    "code": self.code,
                }
            },
            status_code=self.status,
        )


@dataclass
class Audit:
    decision: Decision = Decision.ALLOW
    risk: float = 0.0
    reasons: list[Reason] = field(default_factory=list)

    def add(self, decision: Decision, risk: float, reasons: list[Reason]) -> None:
        if DECISION_ORDER[decision] > DECISION_ORDER[self.decision]:
            self.decision = decision
        self.risk = max(self.risk, risk)
        self.reasons = sorted(
            [*self.reasons, *reasons], key=lambda reason: reason.score, reverse=True
        )[:32]


@dataclass(frozen=True)
class UpstreamReply:
    body: bytes
    media: str
    first_body_byte_ms: float
    total_ms: float


def configured_upstream() -> httpx.URL | None:
    origin = getenv("PI_FIREWALL_RESPONSES_UPSTREAM", "").strip()
    if not origin:
        return None
    try:
        url = httpx.URL(origin)
    except httpx.InvalidURL as error:
        raise ValueError("Invalid PI_FIREWALL_RESPONSES_UPSTREAM URL.") from error
    if (
        url.scheme != "http"
        or url.host != "127.0.0.1"
        or url.port is None
        or url.path != "/"
        or url.query
        or url.fragment
        or url.userinfo
    ):
        raise ValueError(
            "PI_FIREWALL_RESPONSES_UPSTREAM must be a plain http://127.0.0.1:PORT origin."
        )
    return url.copy_with(path="/v1/responses")


async def bounded_body(chunks: AsyncIterable[bytes], error: GatewayError) -> bytes:
    data = bytearray()
    async for chunk in chunks:
        if len(data) + len(chunk) > MAX_BODY:
            raise error
        data.extend(chunk)
    return bytes(data)


def parse_request(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError) as error:
        raise GatewayError(400, "invalid_json", "Expected a JSON object.") from error
    if not isinstance(payload, dict):
        raise GatewayError(400, "invalid_request", "Expected a JSON object.")
    if not isinstance(payload.get("model"), str) or not payload["model"].strip():
        raise GatewayError(400, "invalid_model", "A model name is required.")
    if "input" in payload and not isinstance(payload["input"], (str, list)):
        raise GatewayError(400, "invalid_input", "Input must be a string or an array.")
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise GatewayError(400, "invalid_stream", "Stream must be a boolean.")
    if payload.get("background"):
        raise GatewayError(
            400, "background_unsupported", "Use a foreground Responses request."
        )
    return payload


def inspect_request(
    payload: dict[str, Any], firewall: Firewall, settings: Settings, audit: Audit
) -> None:
    def prompt(text: str) -> str:
        validate_text(text)
        verdict = firewall.inspect(text, settings)
        audit.add(verdict.decision, verdict.risk, verdict.reasons)
        return WITHHELD_PROMPT if verdict.decision == Decision.SANITIZE else text

    @lru_cache(maxsize=16)
    def document(text: str) -> str:
        validate_text(text)
        if not settings.mid_enabled:
            return text
        result = scan(
            Document("tool-result", "Retrieved tool result", text),
            firewall.patterns,
            settings,
        )
        if not result.reasons:
            return text
        audit.add(
            Decision.SANITIZE,
            max(
                settings.sanitize_threshold,
                *(reason.score for reason in result.reasons),
            ),
            result.reasons,
        )
        return (
            result.document.body if result.document is not None else WITHHELD_DOCUMENT
        )

    items = payload.get("input")
    if isinstance(items, str):
        payload["input"] = prompt(items)
    elif isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                raise GatewayError(
                    400, "invalid_input", "Each input item must be an object."
                )
            kind = item.get("type")
            if kind is not None and not isinstance(kind, str):
                raise GatewayError(
                    400, "invalid_input", "The input item type must be a string."
                )
            if kind in TOOL_OUTPUT_TYPES:
                rewrite_text(item, "output", document)
            elif kind == "shell_call_output":
                for output in (
                    item.get("output", [])
                    if isinstance(item.get("output"), list)
                    else []
                ):
                    if isinstance(output, dict):
                        for field_name in ("stdout", "stderr"):
                            rewrite_text(output, field_name, document)
            elif kind in (None, "message") and item.get("role") == "user":
                rewrite_text(item, "content", prompt)


def validate_text(text: str) -> None:
    try:
        length = len(text.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise GatewayError(
            400, "invalid_text", "Input text must be valid Unicode."
        ) from error
    if length > MAX_TEXT:
        raise GatewayError(
            413, "text_too_large", "A text item exceeds the local gateway limit."
        )


def rewrite_text(item: dict[str, Any], name: str, check: Callable[[str], str]) -> None:
    value = item.get(name)
    if isinstance(value, str):
        item[name] = check(value)
    elif isinstance(value, list):
        for part in value:
            if (
                isinstance(part, dict)
                and part.get("type") == "input_text"
                and isinstance(part.get("text"), str)
            ):
                part["text"] = check(part["text"])


def argument_text(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        try:
            structured = json.loads(value)
        except ValueError:
            structured = None
        if isinstance(structured, (dict, list)):
            yield from string_values(structured)
        else:
            yield value
    else:
        yield from string_values(value)


def string_values(value: Any) -> Iterator[str]:
    pending = [value]
    while pending:
        part = pending.pop()
        if isinstance(part, str):
            yield part
        elif isinstance(part, dict):
            pending.extend(part.values())
        elif isinstance(part, list):
            pending.extend(part)


def tool_arguments(item: Any) -> Iterator[str]:
    if not isinstance(item, dict) or not isinstance(item.get("type"), str):
        return
    field = TOOL_ARGUMENT_FIELDS.get(item["type"])
    if field:
        yield from argument_text(item.get(field))


def response_text(response: Any, tool_text: list[str]) -> Iterator[str]:
    if (
        not isinstance(response, dict)
        or response.get("object") != "response"
        or not isinstance(response.get("output"), list)
    ):
        raise ValueError("Malformed response object.")
    for item in response["output"]:
        tool_text.extend(tool_arguments(item))
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if (
                isinstance(part, dict)
                and part.get("type") == "output_text"
                and isinstance(part.get("text"), str)
            ):
                yield part["text"]


def sse_events(raw: bytes) -> Iterator[dict[str, Any]]:
    lines: list[str] = []
    wire = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n") + "\n"
    for line in wire.split("\n"):
        if line.startswith("data:"):
            lines.append(line[5:].lstrip(" "))
        elif not line and lines:
            data = "\n".join(lines)
            lines = []
            if data != "[DONE]":
                event = json.loads(data)
                if not isinstance(event, dict):
                    raise ValueError("Malformed event data.")
                yield event


def inspect_response(
    raw: bytes, stream: bool, settings: Settings, audit: Audit
) -> None:
    final: list[str] = []
    done: list[str] = []
    deltas: list[str] = []
    tool_text: list[str] = []
    tool_deltas: dict[tuple[str, str, str], list[str]] = {}
    try:
        if stream:
            seen_terminal = False
            for event in sse_events(raw):
                kind = event.get("type")
                if kind in ("response.completed", "response.incomplete"):
                    seen_terminal = True
                    final.extend(response_text(event.get("response"), tool_text))
                elif kind == "response.output_text.delta" and isinstance(
                    event.get("delta"), str
                ):
                    deltas.append(event["delta"])
                elif kind == "response.output_text.done" and isinstance(
                    event.get("text"), str
                ):
                    done.append(event["text"])
                elif kind in ("response.failed", "error"):
                    raise ValueError("The upstream emitted an error.")
                elif kind in (
                    "response.output_item.added",
                    "response.output_item.done",
                ):
                    tool_text.extend(tool_arguments(event.get("item")))
                elif isinstance(kind, str):
                    stem, _, stage = kind.rpartition(".")
                    if stem in ARGUMENT_EVENTS:
                        if stage == "delta" and isinstance(event.get("delta"), str):
                            key = (
                                stem,
                                str(event.get("item_id")),
                                str(event.get("output_index")),
                            )
                            tool_deltas.setdefault(key, []).append(event["delta"])
                        elif stage == "done":
                            tool_text.extend(
                                argument_text(event.get(ARGUMENT_EVENTS[stem]))
                            )
            if not seen_terminal:
                raise ValueError("The upstream stream had no final response.")
            for fragments in tool_deltas.values():
                tool_text.extend(argument_text("".join(fragments)))
        else:
            final.extend(response_text(json.loads(raw), tool_text))
    except (ValueError, RecursionError) as error:
        raise GatewayError(
            502,
            "invalid_upstream",
            "The local model returned an invalid Responses payload.",
        ) from error

    if settings.advanced_enabled:
        for text in ("".join(final or done), "".join(deltas), *tool_text):
            if len(text) > MAX_TEXT:
                raise GatewayError(
                    502,
                    "output_too_large",
                    "The output exceeds the local inspection limit.",
                )
            if text:
                findings = inspect_output(text, "", settings.allowed_domains)
                if findings:
                    audit.add(Decision.BLOCK, 1.0, findings)
                    raise GatewayError(
                        400,
                        "firewall_blocked",
                        "The firewall withheld the model output.",
                    )


async def call_upstream(
    upstream: httpx.URL, payload: dict[str, Any], stream: bool
) -> UpstreamReply:
    started = perf_counter()
    media = "text/event-stream" if stream else "application/json"
    size_error = GatewayError(
        502, "upstream_too_large", "The local model response exceeds the gateway limit."
    )
    try:
        async with (
            httpx.AsyncClient(
                timeout=httpx.Timeout(60, connect=3), trust_env=False
            ) as client,
            client.stream(
                "POST", upstream, json=payload, headers={"Accept": media}
            ) as reply,
        ):
            if not reply.is_success:
                raise GatewayError(
                    502, "upstream_error", "The local model rejected the request."
                )
            actual_media = (
                reply.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            )
            if actual_media != media:
                raise GatewayError(
                    502,
                    "invalid_upstream",
                    "The local model returned an unexpected content type.",
                )
            first_body_byte_ms: float | None = None

            async def timed_body() -> AsyncIterator[bytes]:
                nonlocal first_body_byte_ms
                async for data in reply.aiter_bytes():
                    if first_body_byte_ms is None:
                        first_body_byte_ms = (perf_counter() - started) * 1000
                    yield data

            raw = await bounded_body(timed_body(), size_error)
            total_ms = (perf_counter() - started) * 1000
            return UpstreamReply(
                raw,
                media,
                total_ms if first_body_byte_ms is None else first_body_byte_ms,
                total_ms,
            )
    except (httpx.HTTPError, ValueError, RecursionError) as error:
        raise GatewayError(
            502, "upstream_unavailable", "The local model response could not be read."
        ) from error


@router.post("/v1/responses")
async def responses(request: Request) -> Response:
    started = perf_counter()
    upstream: httpx.URL | None = request.app.state.responses_upstream
    if upstream is None:
        return GatewayError(
            503,
            "gateway_disabled",
            "Configure the local Responses upstream to enable this route.",
        ).response()
    server = request.scope.get("server")
    if server and upstream.port == server[1]:
        return GatewayError(
            503, "gateway_loop", "Use a separate port for the Responses upstream."
        ).response()
    with request.app.state.lock:
        firewall: Firewall = request.app.state.firewall
        settings: Settings = request.app.state.settings
    audit = Audit()
    timing: list[str] = []
    try:
        invalid_size = GatewayError(
            413, "request_too_large", "The request exceeds the local gateway limit."
        )
        payload = parse_request(await bounded_body(request.stream(), invalid_size))
        await run_in_threadpool(inspect_request, payload, firewall, settings, audit)
        if audit.decision == Decision.BLOCK:
            raise GatewayError(
                400, "firewall_blocked", "The firewall blocked this request."
            )
        stream = payload.get("stream") is True
        upstream_reply = await call_upstream(upstream, payload, stream)
        timing.extend(
            (
                f"upstream-first-body-byte;dur={upstream_reply.first_body_byte_ms:.2f}",
                f"upstream-download;dur={upstream_reply.total_ms:.2f}",
            )
        )
        checked = perf_counter()
        await run_in_threadpool(
            inspect_response, upstream_reply.body, stream, settings, audit
        )
        timing.append(f"output-inspection;dur={(perf_counter() - checked) * 1000:.2f}")
        result = Response(upstream_reply.body, media_type=upstream_reply.media)
    except GatewayError as error:
        result = error.response()
        audit.add(
            Decision.BLOCK,
            1.0,
            [Reason(layer="responses", score=1, evidence=error.code)],
        )

    result.headers["X-PI-Firewall-Decision"] = audit.decision
    store: Store = request.app.state.store
    await run_in_threadpool(
        store.record,
        original="[Responses API request]",
        normalized="",
        decision=audit.decision,
        risk=audit.risk,
        reasons=[
            (
                reason
                if reason.layer in {"responses", "moderation"}
                else reason.model_copy(
                    update={"evidence": "Responses gateway finding."}
                )
            )
            for reason in audit.reasons
        ],
        latency_ms=(perf_counter() - started) * 1000,
    )
    timing.append(f"gateway-total;dur={(perf_counter() - started) * 1000:.2f}")
    result.headers["Server-Timing"] = ", ".join(timing)
    return result
