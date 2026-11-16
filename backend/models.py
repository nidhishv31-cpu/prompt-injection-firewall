from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from backend.pipeline.policy import Decision, Reason, Rule
from backend.victim_app.documents import DOCUMENTS

DocumentID = Annotated[str, StringConstraints(min_length=1, max_length=40)]


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=12000)
    session_id: UUID | None = None
    document_ids: list[DocumentID] = Field(default_factory=list, max_length=20)

    @field_validator("document_ids")
    @classmethod
    def known_documents(cls, values: list[str]) -> list[str]:
        if any(value not in DOCUMENTS for value in values):
            raise ValueError("Select documents from the built-in collection.")
        return values


class ChatResponse(BaseModel):
    session_id: UUID
    decision: Decision
    risk: float
    normalized: str
    reasons: list[Reason]
    response: str
    latency_ms: float


class PromptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=12000)
    source: Literal["codex", "claude"]


class PromptResponse(BaseModel):
    decision: Decision
    risk: float


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["codex", "claude"]
    cwd: str = Field(default="", max_length=1200)
    tool: str = Field(min_length=1, max_length=150)
    arguments: dict[str, Any]


class RulesUpdate(BaseModel):
    flag_threshold: float
    sanitize_threshold: float
    block_threshold: float
    phrases: list[Rule] = Field(max_length=250)
