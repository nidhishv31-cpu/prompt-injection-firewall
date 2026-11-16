import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import app
from backend.pipeline.aho_corasick import AhoCorasick
from backend.pipeline.normalizer import normalize
from backend.pipeline.policy import Decision, Patterns, Rule, decide, fuse
from backend.training.train_classifier import (
    predict,
    select_threshold,
    split_cases,
    train,
)


def test_aho_corasick_matches_naive_search() -> None:
    rng = random.Random(17)
    for _ in range(100):
        text = "".join(rng.choices("abcd", k=50))
        phrases = {"".join(rng.choices("abcd", k=rng.randint(1, 6))) for _ in range(20)}
        assert sorted(AhoCorasick(phrases).find(text)) == sorted(
            (i, phrase)
            for i in range(len(text))
            for phrase in phrases
            if text.startswith(phrase, i)
        )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ＳаM\u200bPLE\t\t word", "sample word"),
        ("c2FtcGxl", "sample"),
        ("73616d706c65", "sample"),
        ("%2573ample", "sample"),
        ("rot13:fnzcyr", "sample"),
    ],
)
def test_normalizer_preserves_original_and_produces_views(
    text: str, expected: str
) -> None:
    result = normalize(text)
    assert result.original == text
    assert expected in result.views
    assert len(result.views) <= 16


def test_normalizer_limits_recursion() -> None:
    assert "sample" not in normalize("%2573ample", depth=1).views


def test_rules_use_boundaries_and_thresholds() -> None:
    patterns = Patterns([Rule(phrase="sample", category="test", weight=0.8)])
    assert patterns.inspect(normalize("samples")) == (0.0, [])
    score, reasons = patterns.inspect(normalize("a SAMPLE."))
    assert score == 0.8
    assert reasons[0].category == "test"
    settings = Settings()
    assert decide(0, settings) == Decision.ALLOW
    assert decide(settings.flag_threshold, settings) == Decision.FLAG
    assert decide(settings.sanitize_threshold, settings) == Decision.SANITIZE
    assert decide(settings.block_threshold, settings) == Decision.BLOCK
    assert fuse(1, 0, settings) == 0.55


def test_classifier_split_calibration_and_explanations() -> None:
    training, validation, test = split_cases()
    sets = [{case.id for case in group} for group in (training, validation, test)]
    assert sum(map(len, sets)) == len(set().union(*sets)) == 284
    model, report = train()
    rows = predict(model, validation)
    assert all(0 <= row["probability"] <= 1 for row in rows)
    assert select_threshold(rows) == report["threshold"]
    assert model.inspect(normalize("A fictional character transition"))[1]


def test_chat_validates_and_persists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "audit.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        assert (
            client.post(
                "/v1/chat", json={"text": "", "document_ids": ["missing"]}
            ).status_code
            == 422
        )
        result = client.post("/v1/chat", json={"text": "How do I fold a sheet?"})
        row = app.state.store.recent()[0]
    assert result.status_code == 200
    assert len(result.json()["reasons"]) >= 2
    assert row.original == "How do I fold a sheet?"
    assert row.normalized == "how do i fold a sheet?"
