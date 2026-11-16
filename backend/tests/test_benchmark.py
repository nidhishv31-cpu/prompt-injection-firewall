import json
from pathlib import Path

import pytest

from backend.eval.benchmark import FIXTURE_DIR, load_cases, run_baseline


def test_fixture_counts_categories_and_unique_ids() -> None:
    attacks = load_cases(FIXTURE_DIR / "corpus.jsonl")
    benign = load_cases(FIXTURE_DIR / "benign.jsonl")
    assert len(attacks) >= 80
    assert len(benign) >= 200
    assert len({case.id for case in [*attacks, *benign]}) == len(attacks) + len(benign)
    assert len({case.text for case in benign}) == len(benign)
    assert {case.category for case in attacks} == {
        "direct_injection",
        "jailbreak_roleplay",
        "system_prompt_extraction",
        "indirect_injection",
        "obfuscated",
        "exfiltration",
        "multi_turn",
    }
    hard_negatives = " ".join(case.text for case in benign).lower()
    assert all(
        word in hard_negatives
        for word in ("previous", "ignore", "system", "instructions")
    )


def test_baseline_scores_the_bundled_corpus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PI_FIREWALL_BACKEND", "unknown")
    first = run_baseline()
    assert first == run_baseline()
    assert first["mode"] == "firewall_off"
    assert first["attack_summary"] == {
        "cases": 84,
        "disclosures": 56,
        "asr": 56 / 84,
    }
    assert first["by_category"]["indirect_injection"]["disclosures"] == 6
    assert first["by_category"]["obfuscated"]["disclosures"] == 2
    assert first["by_category"]["multi_turn"]["disclosures"] == 8
    assert len(first["missed_ids"]) == 28
    assert (first["benign_cases"], first["benign_disclosures"]) == (200, 0)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", "", "nonempty strings"),
        ("expected_leak", 1, "must be boolean"),
        ("turns", [], "nonempty list"),
        ("turns", [{"event": "invalid"}], "valid Event"),
        ("turns", [{"label": 9}], "must be strings"),
        ("documents", ["missing"], "built-in IDs"),
    ],
)
def test_loader_reports_invalid_fixture_location(
    field: str, value: object, message: str, tmp_path: Path
) -> None:
    fixture = tmp_path / "invalid.jsonl"
    row = {
        "id": "CASE-01",
        "category": "benign",
        "text": "Hello",
        "expected_leak": False,
    }
    row[field] = value
    fixture.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=rf"invalid\.jsonl:1: .*{message}"):
        load_cases(fixture)


def test_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate.jsonl"
    row = {
        "id": "CASE-01",
        "category": "benign",
        "text": "Hello",
        "expected_leak": False,
    }
    fixture.write_text((json.dumps(row) + "\n") * 2, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate id"):
        load_cases(fixture)


def test_baseline_validates_the_corpus_roles() -> None:
    attack = FIXTURE_DIR / "corpus.jsonl"
    benign = FIXTURE_DIR / "benign.jsonl"
    with pytest.raises(ValueError, match="disclosure-targeting cases"):
        run_baseline(benign, benign)
    with pytest.raises(ValueError, match="non-disclosure controls"):
        run_baseline(attack, attack)
