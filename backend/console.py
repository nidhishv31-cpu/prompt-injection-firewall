from collections import Counter
from datetime import UTC
from statistics import median, quantiles
from time import perf_counter
from typing import Annotated

from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from backend.config import Settings
from backend.db import Store
from backend.eval.benchmark import Case
from backend.eval.suite import run_case
from backend.models import RulesUpdate
from backend.pipeline.doc_scanner import scan
from backend.pipeline.firewall import Firewall
from backend.pipeline.policy import Decision, Patterns
from backend.victim_app.documents import DOCUMENTS, Document

router = APIRouter(prefix="/api")


class DocumentRequest(BaseModel):
    text: str = Field(min_length=1, max_length=24000)


class LabRequest(BaseModel):
    case_id: Annotated[str, Field(max_length=80)] | None = None


class NoteRequest(BaseModel):
    note: str = Field(
        min_length=1, max_length=60, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$"
    )


@router.get("/guarded-notes")
def guarded_notes(request: Request) -> list[dict[str, str]]:
    notes: dict[str, Document] = request.app.state.notes
    return [{"id": note.slug, "title": note.title} for note in notes.values()]


@router.post("/guarded-notes/read")
def read_guarded_note(body: NoteRequest, request: Request) -> dict[str, str]:
    started = perf_counter()
    note = request.app.state.notes.get(body.note)
    if note is None:
        raise HTTPException(404, "Guarded note not found.")
    with request.app.state.lock:
        settings: Settings = request.app.state.settings
        firewall: Firewall = request.app.state.firewall
    if not settings.mid_enabled:
        raise HTTPException(503, "The document inspection tier is disabled.")
    result = scan(note, firewall.patterns, settings)
    decision = Decision.SANITIZE if result.reasons else Decision.ALLOW
    request.app.state.store.record(
        original="[Guarded note retrieval]",
        normalized="",
        decision=decision,
        risk=max((reason.score for reason in result.reasons), default=0),
        reasons=[
            reason.model_copy(update={"evidence": "Guarded retrieval finding."})
            for reason in result.reasons
        ],
        latency_ms=(perf_counter() - started) * 1000,
    )
    text = (
        result.document.body
        if result.document
        else "[Tool result withheld by the prompt firewall.]"
    )
    return {"decision": decision, "text": text}


def apply_rules(app: FastAPI, update: RulesUpdate, persist: bool = True) -> None:
    payload = update.model_dump(mode="json")
    values = app.state.settings.model_dump()
    values.update({name: value for name, value in payload.items() if name != "phrases"})
    settings = Settings.model_validate(values)
    patterns = Patterns(update.phrases)
    current: Firewall = app.state.firewall
    if persist:
        app.state.store.save_rules(payload)
    app.state.settings = settings
    app.state.firewall = Firewall(patterns, current.classifier, current.similarity)


@router.get("/documents")
def documents() -> list[dict[str, str]]:
    return [
        {"id": document.slug, "title": document.title}
        for document in DOCUMENTS.values()
    ]


@router.post("/scan")
def scan_document(body: DocumentRequest, request: Request) -> dict[str, object]:
    with request.app.state.lock:
        settings: Settings = request.app.state.settings
        firewall: Firewall = request.app.state.firewall
    result = scan(
        Document("preview", "Pasted document", body.text), firewall.patterns, settings
    )
    return {
        "withheld": result.document is None,
        "text": result.document.body if result.document else "",
        "reasons": result.reasons,
    }


@router.get("/lab")
def lab_cases(request: Request) -> list[dict[str, str]]:
    cases: dict[str, Case] = request.app.state.cases
    return [
        {"id": case.id, "category": case.category, "text": case.text}
        for case in cases.values()
    ]


@router.post("/lab")
def compare(body: LabRequest, request: Request) -> dict[str, object]:
    cases: dict[str, Case] = request.app.state.cases
    if body.case_id is not None and body.case_id not in cases:
        raise HTTPException(404, "Choose a bundled scenario.")
    with request.app.state.lock:
        settings: Settings = request.app.state.settings
        firewall: Firewall = request.app.state.firewall
    off = settings.model_copy(
        update={"base_enabled": False, "mid_enabled": False, "advanced_enabled": False}
    )
    rows = [cases[body.case_id]] if body.case_id else list(cases.values())
    outputs = []
    for case in rows:
        _, leaked_off, out_off = run_case(firewall, off, case)
        alert, leaked_on, out_on = run_case(firewall, settings, case)
        outputs.append(
            {
                "id": case.id,
                "category": case.category,
                "alert": alert,
                "off": {"disclosed": leaked_off, "response": out_off},
                "on": {"disclosed": leaked_on, "response": out_on},
            }
        )
    return {
        "count": len(outputs),
        "off_disclosures": sum(result["off"]["disclosed"] for result in outputs),
        "on_disclosures": sum(result["on"]["disclosed"] for result in outputs),
        "cases": outputs,
    }


@router.get("/model")
def model_metrics(request: Request) -> dict[str, object]:
    return request.app.state.metrics


@router.get("/rules")
def get_rules(request: Request) -> RulesUpdate:
    with request.app.state.lock:
        config: Settings = request.app.state.settings
        firewall: Firewall = request.app.state.firewall
    return RulesUpdate(
        flag_threshold=config.flag_threshold,
        sanitize_threshold=config.sanitize_threshold,
        block_threshold=config.block_threshold,
        phrases=list(firewall.patterns.rules.values()),
    )


@router.put("/rules")
def put_rules(body: RulesUpdate, request: Request) -> RulesUpdate:
    try:
        with request.app.state.lock:
            apply_rules(request.app, body)
    except (ValueError, ValidationError) as error:
        raise HTTPException(422, str(error)) from error
    return body


@router.get("/dashboard")
def dashboard(request: Request) -> dict[str, object]:
    store: Store = request.app.state.store
    records = store.recent()
    counts = Counter(row.decision for row in records)
    categories: Counter[str] = Counter()
    times: dict[str, dict[str, int]] = {}
    for row in reversed(records):
        period = row.created.replace(
            minute=0, second=0, microsecond=0, tzinfo=UTC
        ).isoformat()
        bucket = times.setdefault(
            period, {"allow": 0, "flag": 0, "sanitize": 0, "block": 0}
        )
        bucket[row.decision] += 1
        categories.update(
            {
                str(reason["category"])
                for reason in row.reasons
                if reason.get("category")
                and (row.decision != "allow" or reason.get("layer") == "moderation")
                and float(reason["score"]) >= 0.64
            }
        )
    latencies = [row.latency_ms for row in records]
    return {
        "total": len(records),
        "counts": counts,
        "series": [{"time": time, **count} for time, count in times.items()],
        "categories": [
            {"name": name, "count": count} for name, count in categories.most_common(6)
        ],
        "latency_p50_ms": median(latencies) if latencies else 0,
        "latency_p95_ms": (
            quantiles(latencies, n=100, method="inclusive")[94]
            if len(latencies) > 1
            else (latencies[0] if latencies else 0)
        ),
    }
