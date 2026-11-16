from backend.config import Settings
from backend.eval.benchmark import FIXTURE_DIR, load_cases
from backend.pipeline.doc_scanner import scan
from backend.pipeline.normalizer import normalize
from backend.pipeline.policy import Patterns, load_rules
from backend.pipeline.similarity import SimilarityIndex
from backend.training.train_classifier import train
from backend.victim_app.documents import DOCUMENTS, Document


def test_doc_scan_withholds_contaminated_document() -> None:
    result = scan(DOCUMENTS["shipping"], Patterns(load_rules()), Settings())
    assert result.document is None
    assert {reason.score for reason in result.reasons} == {0, 1}


def test_doc_scan_removes_hidden_tree_but_preserves_visible_text() -> None:
    input_document = Document(
        "doc",
        "Demo",
        "<p>Visible</p><!-- quiet --><i hidden><b>hidden</b></i> Sam\u200bple",
    )
    result = scan(input_document, Patterns([]), Settings())
    assert result.document is not None
    assert (
        result.document.body
        == "[BEGIN UNTRUSTED DOCUMENT]\nVisible Sample\n[END UNTRUSTED DOCUMENT]"
    )
    assert result.reasons[0].layer == "documents"


def test_doc_scan_handles_self_closed_and_malformed_hidden_elements() -> None:
    input_document = Document("doc", "Demo", "<span hidden/>Keep <div hidden><b>Hidden")
    result = scan(input_document, Patterns([]), Settings())
    assert result.document is not None
    assert "\nKeep\n" in result.document.body
    assert "Hidden" not in result.document.body


def test_similarity_identifies_known_fixture() -> None:
    model, _ = train()
    attacks = load_cases(FIXTURE_DIR / "corpus.jsonl")
    index = SimilarityIndex(model, attacks)
    found = index.nearest(normalize(attacks[0].text).views)
    assert found.id == attacks[0].id
    assert found.score > 0.99
