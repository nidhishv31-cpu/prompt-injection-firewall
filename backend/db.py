from datetime import UTC, datetime
from os import getenv
from pathlib import Path

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.engine import URL, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from backend.config import ROOT
from backend.models import ChatResponse
from backend.pipeline.policy import Decision, Reason


class Base(DeclarativeBase):
    pass


class RequestLog(Base):
    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    original: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(12))
    risk: Mapped[float] = mapped_column(Float)
    reasons: Mapped[list[dict[str, object]]] = mapped_column(JSON)
    latency_ms: Mapped[float] = mapped_column(Float)


class RuleOverride(Base):
    __tablename__ = "rule_override"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data: Mapped[dict[str, object]] = mapped_column(JSON)


class Store:
    def __init__(self, path: Path | None = None) -> None:
        path = path or Path(
            getenv("PI_FIREWALL_DB", str(ROOT / "generated" / "firewall.sqlite3"))
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(URL.create("sqlite", database=str(path)))
        Base.metadata.create_all(self.engine)

    def add(self, original: str, result: ChatResponse) -> None:
        self.record(
            original=original,
            normalized=result.normalized,
            decision=result.decision,
            risk=result.risk,
            reasons=result.reasons,
            latency_ms=result.latency_ms,
        )

    def record(
        self,
        *,
        original: str,
        normalized: str,
        decision: Decision,
        risk: float,
        reasons: list[Reason],
        latency_ms: float,
    ) -> None:
        with Session(self.engine) as session:
            session.add(
                RequestLog(
                    original=original,
                    normalized=normalized,
                    decision=decision,
                    risk=risk,
                    reasons=[reason.model_dump(mode="json") for reason in reasons],
                    latency_ms=latency_ms,
                )
            )
            session.commit()

    def recent(self) -> list[RequestLog]:
        with Session(self.engine) as session:
            return list(
                session.scalars(
                    select(RequestLog).order_by(RequestLog.id.desc()).limit(500)
                )
            )

    def read_rules(self) -> dict[str, object] | None:
        with Session(self.engine) as session:
            override = session.get(RuleOverride, 1)
            return override.data if override else None

    def save_rules(self, value: dict[str, object]) -> None:
        with Session(self.engine) as session:
            session.merge(RuleOverride(id=1, data=value))
            session.commit()
