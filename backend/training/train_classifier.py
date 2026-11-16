import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TypedDict

import joblib
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import train_test_split

from backend.config import ROOT
from backend.eval.benchmark import FIXTURE_DIR, Case, load_cases
from backend.pipeline.classifier import Classifier, fit_classifier
from backend.pipeline.normalizer import clean

MODEL_PATH = ROOT / "generated" / "classifier.joblib"


class Prediction(TypedDict):
    id: str
    category: str
    label: int
    probability: float


def cases() -> list[Case]:
    return load_cases(FIXTURE_DIR / "corpus.jsonl") + load_cases(
        FIXTURE_DIR / "benign.jsonl"
    )


def split_cases() -> tuple[list[Case], list[Case], list[Case]]:
    dataset = cases()
    train, rest = train_test_split(
        dataset,
        test_size=0.30,
        stratify=[case.expected_leak for case in dataset],
        random_state=42,
    )
    validation, test = train_test_split(
        rest,
        test_size=0.50,
        stratify=[case.expected_leak for case in rest],
        random_state=42,
    )
    return train, validation, test


def predict(model: Classifier, rows: list[Case]) -> list[Prediction]:
    return [
        {
            "id": case.id,
            "category": case.category,
            "label": int(case.expected_leak),
            "probability": score,
        }
        for case, score in zip(
            rows, model.probabilities([clean(case.text) for case in rows]), strict=True
        )
    ]


def select_threshold(predictions: list[Prediction], target_fpr: float = 0.05) -> float:
    negatives = sum(not row["label"] for row in predictions)
    scores = sorted({1.0, *(row["probability"] for row in predictions)})
    for threshold in scores:
        false_positives = sum(
            not row["label"] and row["probability"] >= threshold for row in predictions
        )
        if false_positives / max(1, negatives) <= target_fpr:
            return threshold
    return 1.0


def train(persist: bool = False) -> tuple[Classifier, dict[str, object]]:
    training, validation, test = split_cases()
    model = fit_classifier(
        [clean(case.text) for case in training],
        [int(case.expected_leak) for case in training],
    )
    predictions = predict(model, test)
    actual = [row["label"] for row in predictions]
    probabilities = [row["probability"] for row in predictions]
    precision, recall, thresholds = precision_recall_curve(actual, probabilities)
    metrics: dict[str, object] = {
        "source": "Held-out synthetic fixture descriptions",
        "split_sizes": [len(training), len(validation), len(test)],
        "threshold": select_threshold(predict(model, validation)),
        "target_fpr": 0.05,
        "average_precision": float(average_precision_score(actual, probabilities)),
        "predictions": predictions,
        "pr_curve": [
            {"precision": float(p), "recall": float(r), "threshold": float(t)}
            for p, r, t in zip(precision[:-1], recall[:-1], thresholds, strict=True)
        ],
    }
    if persist:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=MODEL_PATH.parent, delete=False) as output:
            temporary = Path(output.name)
        try:
            joblib.dump((model, metrics), temporary)
            os.replace(temporary, MODEL_PATH)
        finally:
            temporary.unlink(missing_ok=True)
    return model, metrics


def load_or_train() -> tuple[Classifier, dict[str, object]]:
    if MODEL_PATH.is_file():
        trained: tuple[Classifier, dict[str, object]] = joblib.load(MODEL_PATH)
        return trained
    return train()


if __name__ == "__main__":
    _, report = train(persist=True)
    print(
        f"Trained the fixture classifier. Held-out average precision: {report['average_precision']}"
    )
