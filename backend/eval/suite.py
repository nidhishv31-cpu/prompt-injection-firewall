import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter

from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from backend.attacks.mutator import fixture_variants
from backend.config import ROOT, Settings, load_settings
from backend.eval.benchmark import Case, run_baseline
from backend.pipeline.conversation_state import SessionRisk
from backend.pipeline.firewall import Firewall
from backend.pipeline.policy import Decision, Patterns, load_rules
from backend.pipeline.similarity import SimilarityIndex
from backend.training.train_classifier import cases, load_or_train, split_cases
from backend.victim_app.chat import DEMO_MARKER, MockLLM
from backend.victim_app.documents import DOCUMENTS

SUITE_PATH = ROOT / "eval" / "suite_results.json"


def summarize_runs(
    labels: list[int], detected: list[int], leaks: list[bool], latencies: list[float]
) -> dict[str, object]:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, detected, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, detected, labels=[0, 1]).ravel().tolist()
    return {
        "asr": sum(leak for label, leak in zip(labels, leaks, strict=True) if label)
        / sum(labels),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "benign_fpr": fp / (fp + tn),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "latency_p50_ms": median(latencies),
        "latency_p95_ms": quantiles(latencies, n=100, method="inclusive")[94],
    }


def run_case(
    firewall: Firewall, settings: Settings, case: Case
) -> tuple[bool, bool, str]:
    session = SessionRisk() if settings.advanced_enabled else None
    chatbot = MockLLM(session.canary if session else "")
    documents = tuple(DOCUMENTS[slug] for slug in case.document_ids)
    verdicts = [
        firewall.chat(chatbot, turn, documents, settings, session)
        for turn in case.turns
    ]
    return (
        any(verdict.decision != Decision.ALLOW for verdict in verdicts),
        any(DEMO_MARKER in verdict.response for verdict in verdicts),
        "\n".join(verdict.response for verdict in verdicts),
    )


def evaluate(
    firewall: Firewall, settings: Settings, rows: list[Case]
) -> dict[str, object]:
    labels, detected, leaks, latency = [], [], [], []
    categories: dict[str, list[int]] = defaultdict(list)
    missed = []
    disclosures = []
    for case in rows:
        started = perf_counter()
        alert, leak, _ = run_case(firewall, settings, case)
        latency.append((perf_counter() - started) * 1000)
        labels.append(int(case.expected_leak))
        detected.append(int(alert))
        leaks.append(leak)
        if case.expected_leak:
            categories[case.category].append(int(alert))
            if not alert:
                missed.append(case.id)
            if leak:
                disclosures.append(case.id)
    result = summarize_runs(labels, detected, leaks, latency)
    result["category_recall"] = {
        category: sum(outcomes) / len(outcomes)
        for category, outcomes in categories.items()
    }
    result["missed_ids"] = missed
    result["disclosure_ids"] = disclosures
    return result


def run_suite(phase: str) -> dict[str, object]:
    classifier, metrics = load_or_train()
    training, validation, _ = split_cases()
    similarity = None if phase == "base" else SimilarityIndex(classifier, training)
    firewall = Firewall(Patterns(load_rules()), classifier, similarity)
    if phase != "base" and firewall.similarity:
        firewall.similarity.compare(training, validation)
    config = load_settings()
    base = config.model_copy(
        update={"base_enabled": True, "mid_enabled": False, "advanced_enabled": False}
    )
    rows = cases()
    off = base.model_copy(update={"base_enabled": False})
    report = {
        "phase": phase,
        "firewall_off": run_baseline(),
        "off_metrics": evaluate(firewall, off, rows),
        "base": evaluate(firewall, base, rows),
        "model": metrics,
    }
    if phase != "base":
        mid = base.model_copy(update={"mid_enabled": True})
        report["mid"] = evaluate(firewall, mid, rows)
        _, _, held_out = split_cases()
        report["ablation_held_out"] = {
            "patterns_only": evaluate(
                firewall,
                base.model_copy(update={"pattern_weight": 1, "classifier_weight": 0}),
                held_out,
            ),
            "ml_only": evaluate(
                firewall,
                base.model_copy(update={"pattern_weight": 0, "classifier_weight": 1}),
                held_out,
            ),
            "combined": evaluate(firewall, base, held_out),
        }
        report["similarity_features"] = (
            firewall.similarity.method if firewall.similarity else None
        )
        report["embedding_comparison"] = (
            firewall.similarity.comparison if firewall.similarity else None
        )
        report["embedding_selected"] = (
            firewall.similarity.selected_method if firewall.similarity else None
        )
    if phase == "advanced":
        advanced = config.model_copy(
            update={"base_enabled": True, "mid_enabled": True, "advanced_enabled": True}
        )
        report["advanced"] = evaluate(firewall, advanced, rows)
        variants = fixture_variants()
        benign = [case for case in rows if not case.expected_leak]
        report["mutated"] = evaluate(
            firewall,
            advanced,
            [*(case for subset in variants.values() for case in subset), *benign],
        )
        report["mutations"] = {
            name: evaluate(firewall, advanced, subset + benign)
            for name, subset in variants.items()
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate the local synthetic fixture corpus."
    )
    parser.add_argument("--phase", choices=("base", "mid", "advanced"), default="base")
    parser.add_argument("--output", type=Path, default=SUITE_PATH)
    args = parser.parse_args()
    report = run_suite(args.phase)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for key in ("off_metrics", "base", "mid", "advanced", "mutated"):
        if key in report:
            result = report[key]
            print(
                f"{key}: ASR {result['asr']:.2%}, recall {result['recall']:.2%}, "
                f"FPR {result['benign_fpr']:.2%}, p95 {result['latency_p95_ms']:.2f}ms"
            )


if __name__ == "__main__":
    main()
