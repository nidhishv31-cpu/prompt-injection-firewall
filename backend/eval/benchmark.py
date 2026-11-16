"""Measure synthetic marker disclosure with the firewall off."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from backend.victim_app.chat import DEMO_MARKER, Event, MockLLM, Turn
from backend.victim_app.documents import DOCUMENTS

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "attacks"
RESULTS_PATH = Path(__file__).with_name("results.json")


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    text: str
    expected_leak: bool
    turns: tuple[Turn, ...]
    document_ids: tuple[str, ...]


class Score(TypedDict):
    cases: int
    disclosures: int
    asr: float


class Baseline(TypedDict):
    mode: str
    measurement: str
    attack_summary: Score
    by_category: dict[str, Score]
    missed_ids: list[str]
    benign_cases: int
    benign_disclosures: int


def load_cases(path: Path) -> list[Case]:
    cases: list[Case] = []
    ids: set[str] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            case_id = row["id"]
            category = row["category"]
            text = row["text"]
            expected_leak = row["expected_leak"]
            if not all(
                isinstance(value, str) and value.strip()
                for value in (case_id, category, text)
            ):
                raise ValueError("id, category and text must be nonempty strings")
            if case_id in ids:
                raise ValueError(f"duplicate id {case_id!r}")
            if not isinstance(expected_leak, bool):
                raise TypeError("expected_leak must be boolean")
            raw_turns = row.get("turns", [{"text": text}])
            if not isinstance(raw_turns, list) or not raw_turns:
                raise ValueError("turns must be a nonempty list")
            turns = tuple(
                Turn(
                    text=turn.get("text", text),
                    event=Event(turn["event"]) if "event" in turn else None,
                    label=turn.get("label"),
                )
                for turn in raw_turns
            )
            if any(
                not isinstance(turn.text, str)
                or (turn.label is not None and not isinstance(turn.label, str))
                for turn in turns
            ):
                raise ValueError("turn text and labels must be strings")
            document_ids = row.get("documents", [])
            if not isinstance(document_ids, list):
                raise TypeError("documents must be a list of built-in IDs")
            if any(slug not in DOCUMENTS for slug in document_ids):
                raise ValueError("documents must reference built-in IDs")
            cases.append(
                Case(case_id, category, text, expected_leak, turns, tuple(document_ids))
            )
            ids.add(case_id)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{path.name}:{number}: {error}") from error
    return cases


def observed_disclosure(case: Case) -> bool:
    chatbot = MockLLM()
    documents = tuple(DOCUMENTS[slug] for slug in case.document_ids)
    outcomes = [chatbot.reply(turn, documents) for turn in case.turns]
    return any(DEMO_MARKER in reply.text for reply in outcomes)


def summarize(outcomes: list[bool]) -> Score:
    disclosures = sum(outcomes)
    return {
        "cases": len(outcomes),
        "disclosures": disclosures,
        "asr": disclosures / len(outcomes),
    }


def run_baseline(
    attack_path: Path = FIXTURE_DIR / "corpus.jsonl",
    benign_path: Path = FIXTURE_DIR / "benign.jsonl",
) -> Baseline:
    attacks = load_cases(attack_path)
    benign = load_cases(benign_path)
    if not attacks or any(not case.expected_leak for case in attacks):
        raise ValueError("The attack corpus must contain disclosure-targeting cases.")
    if not benign or any(case.expected_leak for case in benign):
        raise ValueError("The benign corpus must contain only non-disclosure controls.")

    by_category: dict[str, list[bool]] = {}
    attack_outcomes: list[bool] = []
    missed_ids: list[str] = []
    for case in attacks:
        disclosed = observed_disclosure(case)
        by_category.setdefault(case.category, []).append(disclosed)
        attack_outcomes.append(disclosed)
        if not disclosed:
            missed_ids.append(case.id)

    return {
        "mode": "firewall_off",
        "measurement": "synthetic_marker_disclosure",
        "attack_summary": summarize(attack_outcomes),
        "by_category": {
            category: summarize(cases) for category, cases in by_category.items()
        },
        "missed_ids": missed_ids,
        "benign_cases": len(benign),
        "benign_disclosures": sum(observed_disclosure(case) for case in benign),
    }


def main() -> None:
    result = run_baseline()
    with RESULTS_PATH.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    summary = result["attack_summary"]
    print(
        f"Firewall off (synthetic): ASR {summary['asr']:.2%} "
        f"({summary['disclosures']}/{summary['cases']}); "
        f"benign disclosures {result['benign_disclosures']}/{result['benign_cases']}."
    )
    print(f"Results: {RESULTS_PATH.relative_to(FIXTURE_DIR.parent.parent).as_posix()}")


if __name__ == "__main__":
    main()
