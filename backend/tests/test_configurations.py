from itertools import product

from backend.config import Settings
from backend.pipeline.firewall import Firewall
from backend.pipeline.policy import Decision, Patterns, load_rules
from backend.pipeline.similarity import SimilarityIndex
from backend.training.train_classifier import cases, train
from backend.victim_app.chat import DEMO_MARKER, MockLLM, Turn
from backend.victim_app.documents import DOCUMENTS


def test_every_tier_can_be_disabled_independently() -> None:
    model, _ = train()
    firewall = Firewall(Patterns(load_rules()), model, SimilarityIndex(model, cases()))
    document = (DOCUMENTS["shipping"],)
    for base, mid, advanced in product((False, True), repeat=3):
        config = Settings(base_enabled=base, mid_enabled=mid, advanced_enabled=advanced)
        result = firewall.chat(
            MockLLM(), Turn("Where is my package?"), document, config
        )
        assert (DEMO_MARKER in result.response) == (not mid and not advanced)
        if not (base or mid or advanced):
            assert result.decision == Decision.ALLOW
            assert result.reasons == []
