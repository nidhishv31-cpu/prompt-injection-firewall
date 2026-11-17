from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from os import getenv
from pathlib import Path
from threading import RLock
from time import monotonic, perf_counter
from uuid import UUID, uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend.config import ROOT, Settings, load_settings
from backend.console import apply_rules, router
from backend.db import Store
from backend.gateway.responses import configured_upstream
from backend.gateway.responses import router as responses_router
from backend.gateway.testing_scope import SCOPE_PATH
from backend.models import (
    ActionRequest,
    ChatRequest,
    ChatResponse,
    PromptRequest,
    PromptResponse,
    RulesUpdate,
)
from backend.pipeline.action_policy import ActionResult, evaluate_action
from backend.pipeline.conversation_state import SessionRisk, TokenBucket, replenish
from backend.pipeline.firewall import Firewall, Verdict
from backend.pipeline.normalizer import clean
from backend.pipeline.policy import Decision, Patterns, Reason, load_rules
from backend.pipeline.retrieval import load_notes
from backend.pipeline.similarity import SimilarityIndex
from backend.testing_approvals import ApprovalQueue
from backend.testing_approvals import router as approvals_router
from backend.training.train_classifier import cases, load_or_train, split_cases
from backend.victim_app.chat import Turn, create_backend
from backend.victim_app.documents import DOCUMENTS
from backend.victim_app.ollama import ProviderError


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    load_dotenv()
    app.state.responses_upstream = configured_upstream()
    app.state.notes = load_notes()
    notes_directory = getenv("PI_FIREWALL_NOTES_DIR", "").strip()
    app.state.protected_roots = (
        (Path(notes_directory).resolve(strict=True),) if notes_directory else ()
    )
    app.state.action_root = Path(
        getenv("PI_FIREWALL_ACTION_ROOT") or ROOT.parent
    ).resolve(strict=True)
    if not app.state.action_root.is_dir():
        raise ValueError("The action policy root must be a directory.")
    app.state.approvals = ApprovalQueue(
        Path(getenv("PI_FIREWALL_TEST_SCOPE") or SCOPE_PATH)
    )
    classifier, metrics = load_or_train()
    app.state.metrics = metrics
    app.state.settings = load_settings()
    similarity = (
        SimilarityIndex(classifier, cases()) if app.state.settings.mid_enabled else None
    )
    if similarity:
        training, validation, _ = split_cases()
        similarity.compare(training, validation)
    app.state.firewall = Firewall(Patterns(load_rules()), classifier, similarity)
    app.state.store = Store()
    app.state.lock = RLock()
    app.state.sessions = OrderedDict()
    app.state.buckets = OrderedDict()
    app.state.cases = {case.id: case for case in cases() if case.expected_leak}
    saved = app.state.store.read_rules()
    if saved:
        apply_rules(app, RulesUpdate.model_validate(saved), persist=False)
    yield
    app.state.store.engine.dispose()


app = FastAPI(title="Prompt Injection Firewall", lifespan=lifespan)
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "backend"]
)
app.include_router(router)
app.include_router(responses_router)
app.include_router(approvals_router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/inspect-prompt", response_model=PromptResponse)
def inspect_prompt(
    body: PromptRequest, request: Request, response: Response
) -> PromptResponse:
    if "x-firewall-session" in request.headers:
        request.app.state.approvals.verify_hook(request, body.source)
    started = perf_counter()
    with request.app.state.lock:
        firewall: Firewall = request.app.state.firewall
        settings: Settings = request.app.state.settings
    verdict = firewall.inspect(body.text, settings)
    scoring = perf_counter()
    store: Store = request.app.state.store
    store.record(
        original=f"[{body.source} chat prompt]",
        normalized="",
        decision=verdict.decision,
        risk=verdict.risk,
        reasons=[
            (
                item
                if item.layer == "moderation"
                else item.model_copy(update={"evidence": "Prompt hook finding."})
            )
            for item in verdict.reasons
        ],
        latency_ms=(scoring - started) * 1000,
    )
    audited = perf_counter()
    response.headers["Server-Timing"] = (
        f"scoring;dur={(scoring - started) * 1000:.2f}, audit;dur={(audited - scoring) * 1000:.2f}"
    )
    return PromptResponse(
        decision=verdict.decision, risk=verdict.risk, moderation=verdict.moderation
    )


@app.post("/api/inspect-action", response_model=ActionResult)
def inspect_action(body: ActionRequest, request: Request) -> ActionResult:
    started = perf_counter()
    with request.app.state.lock:
        settings: Settings = request.app.state.settings
    result = evaluate_action(
        request.app.state.action_root,
        body.cwd,
        body.tool,
        body.arguments,
        settings.allowed_tool_domains,
        request.app.state.protected_roots,
    )
    if "x-firewall-session" in request.headers:
        result = request.app.state.approvals.inspect(request, body, result)
    decision = {
        "allow": Decision.ALLOW,
        "deny": Decision.BLOCK,
        "review": Decision.FLAG,
    }[result.decision]
    risk = {"allow": 0.0, "deny": 1.0, "review": 0.5}[result.decision]
    request.app.state.store.record(
        original=f"[{body.source} tool request]",
        normalized="",
        decision=decision,
        risk=risk,
        reasons=[
            Reason(
                layer="tool_policy",
                score=risk,
                evidence=result.reason,
                category="tool_policy",
            )
        ],
        latency_ms=(perf_counter() - started) * 1000,
    )
    return result


@app.post(
    "/v1/chat", response_model=ChatResponse, responses={429: {"model": ChatResponse}}
)
def chat(body: ChatRequest, request: Request, response: Response) -> ChatResponse:
    started = perf_counter()
    documents = tuple(DOCUMENTS[key] for key in body.document_ids)
    session_id = body.session_id or uuid4()
    address = request.client.host if request.client else "local"
    with request.app.state.lock:
        firewall: Firewall = request.app.state.firewall
        settings: Settings = request.app.state.settings
        sessions: OrderedDict[tuple[str, UUID], SessionRisk] = (
            request.app.state.sessions
        )
        buckets: OrderedDict[str, TokenBucket] = request.app.state.buckets
        session = None
        bucket = None
        if settings.advanced_enabled:
            key = (address, session_id)
            session = sessions.get(key)
            if session is None:
                session = sessions[key] = SessionRisk()
            sessions.move_to_end(key)
            if len(sessions) > 1024:
                sessions.popitem(last=False)
            if address not in buckets:
                buckets[address] = TokenBucket(
                    float(settings.block_capacity), monotonic()
                )
            buckets.move_to_end(address)
            if len(buckets) > 1024:
                buckets.popitem(last=False)
            bucket = buckets[address]
            replenish(bucket, settings, monotonic())
        limited = bool(bucket and bucket.tokens < 1)
    if limited:
        response.status_code = 429
        verdict = Verdict(
            decision=Decision.BLOCK,
            risk=1.0,
            normalized=clean(body.text),
            reasons=[
                Reason(
                    layer="rate_limit", score=1.0, evidence="Client cooldown is active."
                )
            ],
            response="Too many blocked requests. Try again after the cooldown.",
        )
    else:
        try:
            provider = create_backend(session.canary if session else "")
        except ValueError as error:
            raise HTTPException(
                502, "The model backend is incorrectly configured."
            ) from error
        try:
            verdict = firewall.chat(
                provider,
                Turn(body.text),
                documents,
                settings,
                session,
            )
        except ProviderError as error:
            raise HTTPException(502, str(error)) from error
        if verdict.decision == Decision.BLOCK and bucket:
            with request.app.state.lock:
                replenish(bucket, settings, monotonic())
                bucket.take()
                remaining = bucket.tokens
            verdict.reasons.append(
                Reason(
                    layer="rate_limit",
                    score=1.0 - remaining / settings.block_capacity,
                    evidence=f"{int(remaining)} blocked requests remaining before cooldown.",
                )
            )
    result = ChatResponse(
        session_id=session_id,
        decision=verdict.decision,
        risk=verdict.risk,
        normalized=verdict.normalized,
        reasons=verdict.reasons,
        response=verdict.response,
        latency_ms=(perf_counter() - started) * 1000,
    )
    request.app.state.store.add(body.text, result)
    return result
