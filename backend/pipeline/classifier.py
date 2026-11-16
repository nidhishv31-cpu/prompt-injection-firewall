from dataclasses import dataclass
from functools import cached_property

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion

from backend.pipeline.normalizer import Normalized


@dataclass
class Classifier:
    features: FeatureUnion
    model: CalibratedClassifierCV

    @cached_property
    def coefficients(self) -> np.ndarray:
        return np.mean(
            [fold.estimator.coef_[0] for fold in self.model.calibrated_classifiers_],
            axis=0,
        )

    @cached_property
    def names(self) -> np.ndarray:
        return self.features.get_feature_names_out()

    def probabilities(self, texts: list[str]) -> list[float]:
        return self.model.predict_proba(self.features.transform(texts))[:, 1].tolist()

    def inspect(
        self, normalized: Normalized, *, matrix: csr_matrix | None = None
    ) -> tuple[float, str]:
        if matrix is None:
            matrix = self.features.transform(list(normalized.views))
        probabilities = self.model.predict_proba(matrix)[:, 1]
        strongest = int(probabilities.argmax())
        vector = matrix[strongest]
        ranked = sorted(
            zip(vector.indices, vector.data, strict=True),
            key=lambda pair: abs(float(pair[1] * self.coefficients[pair[0]])),
            reverse=True,
        )
        evidence = ", ".join(
            f"{self.names[index].replace('words__', 'word ').replace('chars__', 'characters ')}"
            f" ({self.coefficients[index] * value:+.2f})"
            for index, value in ranked[:5]
        )
        return (
            float(probabilities[strongest]),
            evidence or "No learned features matched.",
        )


def fit_classifier(texts: list[str], labels: list[int]) -> Classifier:
    features = FeatureUnion(
        [
            ("words", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)),
            (
                "chars",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2),
            ),
        ]
    )
    matrix = features.fit_transform(texts)
    classifier = CalibratedClassifierCV(
        LogisticRegression(class_weight="balanced", max_iter=500, random_state=42),
        cv=4,
        method="sigmoid",
    )
    return Classifier(features, classifier.fit(matrix, labels))
