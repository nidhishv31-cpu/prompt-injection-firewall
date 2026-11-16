import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.config import ModerationMode, ModerationSettings, Settings
from backend.main import app
from backend.pipeline.firewall import Firewall
from backend.pipeline.moderation import ModerationOutcome, moderate
from backend.pipeline.policy import Decision, Patterns
from backend.pipeline.similarity import SimilarityIndex
from backend.training.train_classifier import cases, load_or_train


def policy(mode: ModerationMode) -> ModerationSettings:
    return ModerationSettings(
        mode=mode, terms=("shit", "fuck", "fucking", "asshole", "मूर्ख")
    )


@pytest.mark.parametrize(
    ("text", "strict", "contextual"),
    [
        ("This is shit.", True, False),
        ("This is ＳＨＩＴ.", True, False),
        ("This is sh\u200bit.", True, False),
        ("You are an asshole.", True, True),
        ("Fuck you.", True, True),
        ("You are a fucking idiot.", True, True),
        ("You are a fucking great colleague.", True, False),
        ('Translate "you are an asshole" from this support note.', True, False),
        ("What is the class name for this assessment?", False, False),
        ("The configured term is मूर्ख.", True, False),
    ],
)
def test_word_match_and_context(text: str, strict: bool, contextual: bool) -> None:
    assert (
        moderate(text, policy(ModerationMode.STRICT)) == ModerationOutcome.BLOCKED
    ) is strict
    assert (
        moderate(text, policy(ModerationMode.CONTEXTUAL)) == ModerationOutcome.BLOCKED
    ) is contextual
    assert (
        moderate(text, policy(ModerationMode.REPORT_ONLY)) == ModerationOutcome.REPORTED
    ) is strict


def test_strict_policy_short_circuits_classifier() -> None:
    classifier = Mock()
    firewall = Firewall(Patterns([]), classifier)
    settings = Settings(moderation=policy(ModerationMode.STRICT))
    verdict = firewall.inspect("This is shit.", settings)
    assert verdict.decision == Decision.BLOCK
    assert verdict.moderation == ModerationOutcome.BLOCKED
    assert not classifier.mock_calls


def test_report_only_and_strict_can_run_independently_of_injection_tiers() -> None:
    firewall = Firewall(Patterns([]), Mock())
    for mode, decision in (
        (ModerationMode.REPORT_ONLY, Decision.ALLOW),
        (ModerationMode.STRICT, Decision.BLOCK),
    ):
        settings = Settings(
            base_enabled=False, mid_enabled=False, moderation=policy(mode)
        )
        verdict = firewall.inspect("This is shit.", settings)
        assert verdict.decision == decision
        assert verdict.reasons[0].category == "vulgar_language"


def test_desktop_route_blocks_without_storing_the_original_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "moderation.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        for origin in ("codex", "claude"):
            reply = client.post(
                "/api/inspect-prompt",
                json={"source": origin, "text": "What a load of bullshit."},
            )
            assert reply.json() == {
                "decision": "block",
                "risk": 1.0,
                "moderation": "blocked",
            }
            assert "scoring;dur=" in reply.headers["Server-Timing"]
        rows = app.state.store.recent()
        assert {reason["layer"] for row in rows for reason in row.reasons} == {
            "moderation"
        }
        assert "bullshit" not in json.dumps(
            [[row.original, row.normalized, row.reasons] for row in rows]
        )


def test_cache_reuses_scoring_and_shared_tfidf_preserves_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classifier, _ = load_or_train()
    index = SimilarityIndex(classifier, cases())
    firewall = Firewall(Patterns([]), classifier, index)
    transform = Mock(wraps=classifier.features.transform)
    monkeypatch.setattr(classifier.features, "transform", transform)
    positive = cases()[0].text
    settings = Settings(inspection_cache_size=2)
    first = firewall.inspect(positive, settings)
    original_reasons = [reason.model_copy() for reason in first.reasons]
    first.reasons.clear()
    replay = firewall.inspect(positive, settings)
    assert transform.call_count == 1
    assert replay.reasons == original_reasons
    uncached = firewall.inspect(
        positive, settings.model_copy(update={"inspection_cache_size": 0})
    )
    assert uncached == replay
    stricter = settings.model_copy(update={"moderation": policy(ModerationMode.STRICT)})
    assert firewall.inspect("This is shit.", stricter).decision == Decision.BLOCK
    assert (
        firewall.inspect("This is shit.", settings).moderation
        == ModerationOutcome.CLEAR
    )
    assert len(firewall._inspection_cache) <= 2


def test_report_only_shows_a_moderation_finding_in_dashboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PI_FIREWALL_DB", str(tmp_path / "report-only.sqlite"))
    with TestClient(app, base_url="http://localhost") as client:
        app.state.settings = Settings(
            base_enabled=False,
            mid_enabled=False,
            moderation=policy(ModerationMode.REPORT_ONLY),
        )
        result = client.post(
            "/api/inspect-prompt", json={"source": "codex", "text": "This is shit."}
        )
        assert result.json() == {
            "decision": "allow",
            "risk": 0.0,
            "moderation": "reported",
        }
        assert "report-only" in app.state.store.recent()[0].reasons[0]["evidence"]
        assert client.get("/api/dashboard").json()["categories"] == [
            {"name": "vulgar_language", "count": 1}
        ]
