from _thread import LockType
from dataclasses import dataclass, field
from threading import Lock

from backend.config import Settings
from backend.pipeline.canary import new_canary


@dataclass
class SessionRisk:
    value: float = 0
    updated: float | None = None
    canary: str = field(default_factory=new_canary)
    lock: LockType = field(default_factory=Lock, repr=False, compare=False)

    def add(self, risk: float, now: float, half_life: float) -> float:
        with self.lock:
            previous = self.updated if self.updated is not None else now
            now = max(now, previous)
            elapsed = now - previous
            residual = self.value * 2 ** (-elapsed / half_life)
            self.value = min(1.0, residual + risk * 0.55)
            self.updated = now
            return self.value


@dataclass
class TokenBucket:
    tokens: float
    updated: float

    def refresh(self, now: float, capacity: int, refill_seconds: float) -> None:
        self.tokens = min(
            float(capacity), self.tokens + max(0.0, now - self.updated) / refill_seconds
        )
        self.updated = now

    def take(self) -> bool:
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


def replenish(bucket: TokenBucket, settings: Settings, now: float) -> None:
    bucket.refresh(now, settings.block_capacity, settings.block_refill_seconds)
