from dataclasses import dataclass, field
from time import monotonic

from backend.config import Settings
from backend.pipeline.classifier import Classifier
from backend.pipeline.conversation_state import SessionRisk
from backend.pipeline.doc_scanner import scan
from backend.pipeline.normalizer import normalize
from backend.pipeline.output_filter import inspect_output
from backend.pipeline.policy import Decision, Patterns, Reason, decide, fuse
from backend.pipeline.similarity import SimilarityIndex
from backend.victim_app.chat import ChatBackend, Reply, Turn
from backend.victim_app.documents import Document


@dataclass
class Verdict:
    decision: Decision = Decision.ALLOW
    risk: float = 0.0
    normalized: str = ""
    reasons: list[Reason] = field(default_factory=list)
    response: str = ""


class Firewall:
    def __init__(
        self,
        patterns: Patterns,
        classifier: Classifier,
        similarity: SimilarityIndex | None = None,
    ) -> None:
        self.patterns = patterns
        self.classifier = classifier
        self.similarity = similarity

    def inspect(self, text: str, settings: Settings) -> Verdict:
        verdict = Verdict(normalized=text)
        if not (settings.base_enabled or settings.mid_enabled):
            return verdict
        normalized = normalize(text)
        reasons: list[Reason] = []
        risk = 0.0
        if settings.base_enabled:
            pattern_score, reasons = self.patterns.inspect(normalized)
            classifier_score, evidence = self.classifier.inspect(normalized)
            risk = fuse(pattern_score, classifier_score, settings)
            if not reasons:
                reasons.append(
                    Reason(
                        layer="patterns",
                        score=pattern_score,
                        evidence="No phrase matched.",
                    )
                )
            reasons.append(
                Reason(layer="classifier", score=classifier_score, evidence=evidence)
            )
        if settings.mid_enabled and self.similarity:
            neighbor = self.similarity.nearest(normalized.views)
            probability = self.similarity.probability(normalized.views)
            if probability is not None:
                reasons.append(
                    Reason(
                        layer="semantic_classifier",
                        score=probability,
                        evidence=self.similarity.selected_method,
                    )
                )
                risk = (
                    fuse(pattern_score, probability, settings)
                    if settings.base_enabled
                    else probability
                )
            reasons.append(
                Reason(
                    layer="similarity",
                    score=neighbor.score,
                    evidence=f"{neighbor.id}: {neighbor.text}",
                    category=neighbor.category,
                )
            )
            if neighbor.score >= settings.similarity_threshold:
                risk = max(
                    risk,
                    settings.flag_threshold
                    + (1 - settings.flag_threshold)
                    * (
                        (neighbor.score - settings.similarity_threshold)
                        / (1 - settings.similarity_threshold)
                    ),
                )
        return Verdict(
            decision=decide(risk, settings),
            risk=risk,
            normalized=normalized.text,
            reasons=reasons,
        )

    def chat(
        self,
        backend: ChatBackend,
        turn: Turn,
        documents: tuple[Document, ...],
        settings: Settings,
        session: SessionRisk | None = None,
    ) -> Verdict:
        verdict = self.inspect(turn.text, settings)
        if settings.advanced_enabled and session:
            accumulated = session.add(
                verdict.risk, monotonic(), settings.decay_half_life
            )
            verdict.risk = max(verdict.risk, accumulated)
            verdict.decision = decide(verdict.risk, settings)
            verdict.reasons.append(
                Reason(
                    layer="conversation",
                    score=accumulated,
                    evidence="Decayed session risk.",
                )
            )
        if verdict.decision == Decision.BLOCK:
            verdict.response = "The firewall blocked this request."
            return verdict
        if verdict.decision == Decision.SANITIZE:
            turn = Turn("The firewall withheld an input with elevated risk.")
        if settings.mid_enabled:
            scanned = [
                scan(document, self.patterns, settings) for document in documents
            ]
            documents = tuple(
                result.document for result in scanned if result.document is not None
            )
            verdict.reasons.extend(
                reason for result in scanned for reason in result.reasons
            )
            if any(result.document is None for result in scanned):
                verdict.risk = max(verdict.risk, settings.sanitize_threshold)
                verdict.decision = Decision.SANITIZE
        reply: Reply = backend.reply(turn, documents)
        verdict.response = reply.text
        if settings.advanced_enabled:
            findings = inspect_output(
                reply.text, session.canary if session else "", settings.allowed_domains
            )
            verdict.reasons.extend(
                findings
                or [
                    Reason(
                        layer="output", score=0, evidence="No output filter finding."
                    )
                ]
            )
            if findings:
                verdict.decision = Decision.BLOCK
                verdict.risk = 1.0
                verdict.response = "The firewall withheld the model output."
        return verdict
