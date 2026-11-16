from enum import StrEnum

import yaml
from pydantic import BaseModel, Field

from backend.config import ROOT, Settings
from backend.pipeline.aho_corasick import AhoCorasick
from backend.pipeline.normalizer import Normalized, clean


class Decision(StrEnum):
    ALLOW = "allow"
    FLAG = "flag"
    SANITIZE = "sanitize"
    BLOCK = "block"


class Reason(BaseModel):
    layer: str
    score: float
    evidence: str
    category: str | None = None


class Rule(BaseModel):
    phrase: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=80)
    weight: float = Field(gt=0, le=1)


class Patterns:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = {clean(rule.phrase): rule for rule in rules}
        if "" in self.rules or len(self.rules) != len(rules):
            raise ValueError("Normalized rule phrases must be nonempty and unique.")
        self.matcher = AhoCorasick(self.rules)

    def inspect(self, normalized: Normalized) -> tuple[float, list[Reason]]:
        matches = {
            phrase
            for view in normalized.views
            for start, phrase in self.matcher.find(view)
            if (start == 0 or not view[start - 1].isalnum())
            and (
                start + len(phrase) == len(view)
                or not view[start + len(phrase)].isalnum()
            )
        }
        reasons = [
            Reason(
                layer="patterns",
                score=rule.weight,
                evidence=rule.phrase,
                category=rule.category,
            )
            for phrase in sorted(matches)
            for rule in (self.rules[phrase],)
        ]
        return max((reason.score for reason in reasons), default=0.0), reasons


def load_rules() -> list[Rule]:
    records = yaml.safe_load(
        (ROOT / "rules" / "phrases.yaml").read_text(encoding="utf-8")
    )
    return [Rule.model_validate(record) for record in records]


def fuse(pattern: float, classifier: float, settings: Settings) -> float:
    total = settings.pattern_weight + settings.classifier_weight
    return (
        settings.pattern_weight * pattern + settings.classifier_weight * classifier
    ) / total


def decide(risk: float, settings: Settings) -> Decision:
    if risk >= settings.block_threshold:
        return Decision.BLOCK
    if risk >= settings.sanitize_threshold:
        return Decision.SANITIZE
    if risk >= settings.flag_threshold:
        return Decision.FLAG
    return Decision.ALLOW
