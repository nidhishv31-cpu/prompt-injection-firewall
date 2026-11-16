import pytest

from backend.victim_app.chat import (
    DEMO_MARKER,
    SYSTEM_PROMPT,
    Event,
    MockLLM,
    Turn,
    create_backend,
)
from backend.victim_app.documents import DOCUMENTS


@pytest.mark.parametrize("event", [Event.OVERRIDE, Event.ROLE_SWITCH])
def test_supported_simulated_event_discloses_marker(event: Event) -> None:
    assert MockLLM().reply(Turn("Demo event", event)).text == DEMO_MARKER


def test_metadata_returns_the_demo_prompt() -> None:
    assert MockLLM().reply(Turn("Demo metadata event", Event.METADATA)).text == (
        SYSTEM_PROMPT
    )
    assert DEMO_MARKER in SYSTEM_PROMPT


def test_ordinary_text_does_not_dispatch_an_event() -> None:
    assert DEMO_MARKER not in MockLLM().reply(Turn("metadata")).text


@pytest.mark.parametrize("slug", ["returns", "shipping", "hours", "pickup", "payments"])
def test_retrieved_hidden_fixture_is_seen_by_mock(slug: str) -> None:
    reply = MockLLM().reply(Turn("Look up policy"), (DOCUMENTS[slug],))
    assert reply.text == DEMO_MARKER


def test_clean_documents_return_titles() -> None:
    reply = MockLLM().reply(
        Turn("Look up store information"), (DOCUMENTS["orders"], DOCUMENTS["recycling"])
    )
    assert reply.text == "Retrieved demo documents: Order status, Recycling."
    assert len(DOCUMENTS) == 20


def test_label_matching_is_literal() -> None:
    chatbot = MockLLM()
    assert (
        chatbot.reply(Turn("Demo label", Event.ENCODED_LABEL, "sample")).text
        == DEMO_MARKER
    )
    assert (
        DEMO_MARKER
        not in chatbot.reply(Turn("Demo label", Event.ENCODED_LABEL, "c2FtcGxl")).text
    )


def test_image_preview_uses_an_inert_fragment() -> None:
    reply = MockLLM().reply(Turn("Demo preview", Event.IMAGE_PREVIEW))
    assert reply.text == f"![{DEMO_MARKER}](#demo-image)"


def test_recall_needs_prior_state_in_the_same_session() -> None:
    chatbot = MockLLM()
    other_chatbot = MockLLM()
    recall = Turn("Recall sample", Event.RECALL)
    assert DEMO_MARKER not in chatbot.reply(recall).text
    assert DEMO_MARKER not in chatbot.reply(Turn("Stage sample", Event.STAGE)).text
    assert DEMO_MARKER not in other_chatbot.reply(recall).text
    assert DEMO_MARKER not in chatbot.reply(Turn("Check store hours")).text
    assert chatbot.reply(recall).text == DEMO_MARKER
    assert DEMO_MARKER not in chatbot.reply(recall).text


def test_backend_defaults_to_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PI_FIREWALL_BACKEND", raising=False)
    assert isinstance(create_backend(), MockLLM)
    monkeypatch.setenv("PI_FIREWALL_BACKEND", "mock")
    assert isinstance(create_backend(), MockLLM)


def test_unknown_backend_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PI_FIREWALL_BACKEND", "unknown")
    with pytest.raises(ValueError, match="must be 'mock'"):
        create_backend()
