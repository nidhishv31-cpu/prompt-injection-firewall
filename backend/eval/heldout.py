"""Score a fixed corpus excluded from training and similarity indexing."""

import argparse
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter
from typing import Any

from backend.config import ROOT, Settings, load_settings
from backend.pipeline.action_policy import evaluate_action
from backend.pipeline.doc_scanner import scan
from backend.pipeline.firewall import Firewall
from backend.pipeline.output_filter import inspect_output
from backend.pipeline.policy import Decision, Patterns, load_rules
from backend.pipeline.similarity import SimilarityIndex
from backend.training.train_classifier import cases, load_or_train
from backend.victim_app.documents import Document

FIXTURES = Path(__file__).with_name("heldout.jsonl")


@dataclass(frozen=True)
class Observation:
    id: str
    expected: bool
    decision: Decision
    milliseconds: float


def score_case(row: dict[str, Any], firewall: Firewall, settings: Settings) -> Decision:
    surface, data = row["surface"], row["input"]
    if surface == "prompt":
        return firewall.inspect(data, settings).decision
    if surface == "document":
        result = scan(
            Document("heldout", "Held-out note", data), firewall.patterns, settings
        )
        return Decision.SANITIZE if result.reasons else Decision.ALLOW
    if surface == "output":
        return (
            Decision.BLOCK
            if inspect_output(data, "", settings.allowed_domains)
            else Decision.ALLOW
        )
    if surface == "action":
        result = evaluate_action(
            ROOT.parent,
            "",
            data["tool"],
            data["arguments"],
            settings.allowed_tool_domains,
        )
        return {
            "allow": Decision.ALLOW,
            "deny": Decision.BLOCK,
            "review": Decision.SANITIZE,
        }[result.decision]
    raise ValueError(f"Unsupported evaluation surface: {surface}.")


def summarize(rows: list[Observation]) -> dict[str, Any]:
    enforced = {Decision.SANITIZE, Decision.BLOCK}
    predicted = [row for row in rows if row.decision != Decision.ALLOW]
    benign = sum(not row.expected for row in rows)
    positive = len(rows) - benign
    missed = [row.id for row in rows if row.expected and row.decision == Decision.ALLOW]
    missed_enforcement = [
        row.id for row in rows if row.expected and row.decision not in enforced
    ]
    false_alerts = [row.id for row in predicted if not row.expected]
    false_holds = [
        row.id for row in rows if not row.expected and row.decision in enforced
    ]
    times = [row.milliseconds for row in rows]
    return {
        "cases": len(rows),
        "benign": benign,
        "positive": positive,
        "alert_recall": (positive - len(missed)) / positive if positive else None,
        "enforcement_recall": (
            (positive - len(missed_enforcement)) / positive if positive else None
        ),
        "benign_alert_rate": len(false_alerts) / benign if benign else None,
        "benign_hold_rate": len(false_holds) / benign if benign else None,
        "missed_alerts": missed,
        "missed_enforcement": missed_enforcement,
        "false_alerts": false_alerts,
        "false_holds": false_holds,
        "p50_ms": median(times),
        "p95_ms": (
            quantiles(times, n=100, method="inclusive")[94]
            if len(times) > 1
            else times[0]
        ),
    }


def evaluate() -> dict[str, Any]:
    source = FIXTURES.read_bytes()
    fixtures = [json.loads(line) for line in source.splitlines() if line.strip()]
    classifier, _ = load_or_train()
    training = cases()
    firewall = Firewall(
        Patterns(load_rules()), classifier, SimilarityIndex(classifier, training)
    )
    settings = load_settings()
    by_surface: dict[str, list[Observation]] = defaultdict(list)
    by_category: dict[str, list[Observation]] = defaultdict(list)
    observations = []
    for row in fixtures:
        started = perf_counter()
        decision = score_case(row, firewall, settings)
        sample = Observation(
            row["id"], row["intervention"], decision, (perf_counter() - started) * 1000
        )
        observations.append(sample)
        by_surface[row["surface"]].append(sample)
        by_category[f"{row['surface']}/{row['category']}"].append(sample)
    return {
        "fixture_sha256": hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest(),
        "synthetic": True,
        "overall": summarize(observations),
        "by_surface": {key: summarize(rows) for key, rows in by_surface.items()},
        "by_category": {key: summarize(rows) for key, rows in by_category.items()},
        "decisions": {row.id: row.decision for row in observations},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = evaluate()
    if args.output:
        args.output.write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    for key, metrics in result["by_surface"].items():
        print(
            f"{key}: {metrics['cases']} cases, alert recall {metrics['alert_recall']:.1%}, "
            f"enforcement recall {metrics['enforcement_recall']:.1%}, "
            f"benign holds {metrics['benign_hold_rate']:.1%}, p95 {metrics['p95_ms']:.2f} ms"
        )
    if args.compare:
        baseline = json.loads(args.compare.read_text(encoding="utf-8"))
        if baseline["fixture_sha256"] != result["fixture_sha256"]:
            parser.error("The saved benchmark uses a different fixture version.")
        changed = [
            key
            for key, decision in result["decisions"].items()
            if decision != baseline["decisions"][key]
        ]
        print(
            f"Decision changes against the saved benchmark: {', '.join(changed) or 'none'}."
        )


if __name__ == "__main__":
    main()
