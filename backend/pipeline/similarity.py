from dataclasses import dataclass
from os import getenv
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.metrics.pairwise import cosine_similarity

from backend.eval.benchmark import Case
from backend.pipeline.classifier import Classifier
from backend.pipeline.normalizer import clean


@dataclass(frozen=True)
class Neighbor:
    id: str
    text: str
    category: str
    score: float


class SimilarityIndex:
    def __init__(self, classifier: Classifier, cases: list[Case]) -> None:
        self.classifier = classifier
        self.cases = tuple(case for case in cases if case.expected_leak)
        self.encoder = None
        self.selected_model: CalibratedClassifierCV | None = None
        self.selected_method = "tfidf"
        self.comparison: dict[str, float] | None = None
        model_dir = getenv("PI_FIREWALL_EMBEDDING_MODEL")
        if model_dir:
            path = Path(model_dir).resolve(strict=True)
            if not path.is_dir():
                raise ValueError("The embedding model must be a local model directory.")
            from sentence_transformers import SentenceTransformer

            self.encoder = SentenceTransformer(
                str(path), local_files_only=True, trust_remote_code=False, device="cpu"
            )
        self.reference = self._encode([clean(case.text) for case in self.cases])

    @property
    def method(self) -> str:
        return "sentence-transformers" if self.encoder else "TF-IDF"

    def _encode(self, texts: list[str]) -> Any:
        if self.encoder:
            return self.encoder.encode(
                texts, normalize_embeddings=True, show_progress_bar=False
            )
        return self.classifier.features.transform(texts)

    def _features(self, texts: list[str], method: str) -> Any:
        embedding = self._encode(texts)
        if method == "combined":
            return hstack(
                [self.classifier.features.transform(texts), csr_matrix(embedding)]
            ).tocsr()
        return embedding

    def compare(self, training: list[Case], validation: list[Case]) -> None:
        if not self.encoder:
            return
        train_text = [clean(case.text) for case in training]
        validation_text = [clean(case.text) for case in validation]
        train_labels = [int(case.expected_leak) for case in training]
        validation_labels = [int(case.expected_leak) for case in validation]
        scores = {
            "tfidf": float(
                average_precision_score(
                    validation_labels, self.classifier.probabilities(validation_text)
                )
            )
        }
        models = {}
        for method in ("embeddings", "combined"):
            model = CalibratedClassifierCV(LogisticRegression(max_iter=500), cv=4)
            model.fit(self._features(train_text, method), train_labels)
            probabilities = model.predict_proba(
                self._features(validation_text, method)
            )[:, 1]
            scores[method] = float(
                average_precision_score(validation_labels, probabilities)
            )
            models[method] = model
        self.selected_method = max(scores, key=lambda method: scores[method])
        self.selected_model = models.get(self.selected_method)
        self.comparison = scores

    def probability(self, views: tuple[str, ...]) -> float | None:
        if not self.selected_model:
            return None
        score = self.selected_model.predict_proba(
            self._features(list(views), self.selected_method)
        )
        return float(np.max(score[:, 1]))

    def nearest(
        self, views: tuple[str, ...], *, tfidf: csr_matrix | None = None
    ) -> Neighbor:
        encoded = (
            tfidf
            if tfidf is not None and self.encoder is None
            else self._encode(list(views))
        )
        scores = cosine_similarity(encoded, self.reference)
        match = int(scores.max(axis=0).argmax())
        case = self.cases[match]
        return Neighbor(
            case.id,
            case.text,
            case.category,
            max(0.0, min(1.0, float(scores[:, match].max()))),
        )
