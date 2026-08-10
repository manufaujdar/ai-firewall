from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

EventScalar: TypeAlias = str | int | float | bool | None
EventSink: TypeAlias = Callable[["PrivacyEvent"], Awaitable[None]]


class PrivacyPhase(StrEnum):
    RECEIVED = "received"
    DETERMINISTIC = "deterministic_detection"
    LOCAL_MODEL = "local_model_detection"
    RESIDUAL = "residual_scan"
    DECISION = "decision"
    PERSISTENCE = "metadata_persistence"
    COMPLETE = "complete"


class EventStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class PrivacyEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    sequence: int = Field(ge=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    phase: PrivacyPhase
    status: EventStatus
    metadata: dict[str, EventScalar] = Field(default_factory=dict)


ALLOWED_METADATA_KEYS = frozenset(
    {
        "decision",
        "duration_ms",
        "finding_count",
        "model_count",
        "model_ids",
        "persistence",
        "policy_version",
        "residual_pass",
        "rule_ids",
    }
)


class EventEmitter:
    """Create metadata-only ordered events for one inspection request."""

    def __init__(self, request_id: str, sink: EventSink | None = None) -> None:
        self.request_id = request_id
        self.sink = sink
        self.sequence = 0

    async def emit(
        self,
        phase: PrivacyPhase,
        status: EventStatus,
        metadata: Mapping[str, EventScalar] | None = None,
    ) -> PrivacyEvent:
        safe_metadata = dict(metadata or {})
        unknown = set(safe_metadata) - ALLOWED_METADATA_KEYS
        if unknown:
            raise ValueError("privacy event metadata contains a forbidden key")
        self.sequence += 1
        event = PrivacyEvent(
            request_id=self.request_id,
            sequence=self.sequence,
            phase=phase,
            status=status,
            metadata=safe_metadata,
        )
        if self.sink is not None:
            await self.sink(event)
        return event
