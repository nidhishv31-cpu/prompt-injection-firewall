from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parent


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    base_enabled: bool = True
    mid_enabled: bool = True
    advanced_enabled: bool = True
    pattern_weight: float = Field(0.55, ge=0, le=1)
    classifier_weight: float = Field(0.45, ge=0, le=1)
    flag_threshold: float = Field(0.35, gt=0, le=1)
    sanitize_threshold: float = Field(0.57, gt=0, le=1)
    block_threshold: float = Field(0.76, gt=0, le=1)
    similarity_threshold: float = Field(0.86, gt=0, lt=1)
    document_threshold: float = Field(0.64, gt=0, le=1)
    decay_half_life: float = Field(180, gt=0)
    block_capacity: int = Field(5, gt=0)
    block_refill_seconds: float = Field(60, gt=0)
    allowed_domains: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_thresholds(self) -> Self:
        if not self.flag_threshold < self.sanitize_threshold < self.block_threshold:
            raise ValueError("Thresholds must increase from flag to sanitize to block.")
        if self.pattern_weight + self.classifier_weight <= 0:
            raise ValueError("At least one fusion weight must be positive.")
        return self


def load_settings() -> Settings:
    return Settings.model_validate(yaml.safe_load((ROOT / "config.yaml").read_text()))
