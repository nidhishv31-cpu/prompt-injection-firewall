from collections import OrderedDict
from dataclasses import dataclass, field, replace
from hashlib import blake2b
from secrets import token_bytes
from threading import RLock
from time import monotonic

from backend.config import Settings
from backend.pipeline.classifier import Classifier
from backend.pipeline.conversation_state import SessionRisk
from backend.pipeline.doc_scanner import scan
from backend.pipeline.moderation import ModerationOutcome, moderate
from backend.pipeline.normalizer import clean, normalize
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
    moderation: ModerationOutcome = ModerationOutcome.CLEAR


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
        self._cache_lock = RLock()
        self._cache_salt = token_bytes(32)
        self._inspection_cache: OrderedDict[tuple[Settings, bytes], Verdict] = (
            OrderedDict()
        )

    def inspect(self, text: str, settings: Settings) -> Verdict:
        capacity = settings.inspection_cache_size
        if not capacity or not (settings.base_enabled or settings.mid_enabled):
            return self._inspect_uncached(text, settings)
        fingerprint = blake2b(
            text.encode("utf-8", errors="surrogatepass"),
            digest_size=24,
            key=self._cache_salt,
        ).digest()
        key = (settings, fingerprint)
        with self._cache_lock:
            hit = self._inspection_cache.get(key)
            if hit is not None:
                self._inspection_cache.move_to_end(key)
        if hit is not None:
            return replace(
                hit,
                normalized=clean(text),
                reasons=[reason.model_copy() for reason in hit.reasons],
            )
        verdict = self._inspect_uncached(text, settings)
        with self._cache_lock:
            self._inspection_cache[key] = replace(
                verdict,
                normalized="",
                reasons=[reason.model_copy() for reason in verdict.reasons],
            )
            self._inspection_cache.move_to_end(key)
            while len(self._inspection_cache) > capacity:
                self._inspection_cache.popitem(last=False)
        return verdict

    def _inspect_uncached(self, text: str, settings: Settings) -> Verdict:
        outcome = moderate(text, settings.moderation)
        if outcome == ModerationOutcome.BLOCKED:
            return Verdict(
                decision=Decision.BLOCK,
                risk=1.0,
                normalized=clean(text),
                reasons=[
                    Reason(
                        layer="moderation",
                        score=1.0,
                        evidence="Vulgar language blocked.",
                        category="vulgar_language",
                    )
                ],
                moderation=outcome,
            )
        verdict = self._inspect_injection(text, settings)
        if outcome == ModerationOutcome.REPORTED:
            verdict.reasons.append(
                Reason(
                    layer="moderation",
                    score=1.0,
                    evidence="Vulgar language matched in report-only mode.",
                    category="vulgar_language",
                )
            )
            verdict.moderation = outcome
        return verdict

    def _inspect_injection(self, text: str, settings: Settings) -> Verdict:
        verdict = Verdict(normalized=text)
        if not (settings.base_enabled or settings.mid_enabled):
            return verdict
        normalized = normalize(text)
        reasons: list[Reason] = []
        risk = 0.0
        tfidf = None
        if settings.base_enabled:
            pattern_score, reasons = self.patterns.inspect(normalized)
            tfidf = self.classifier.features.transform(list(normalized.views))
            classifier_score, evidence = self.classifier.inspect(
                normalized, matrix=tfidf
            )
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
            neighbor = self.similarity.nearest(
                normalized.views,
                tfidf=tfidf if self.similarity.classifier is self.classifier else None,
            )
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
