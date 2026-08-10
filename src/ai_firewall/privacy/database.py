from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ai_firewall.models import Action


@dataclass(frozen=True, slots=True)
class InspectionSummary:
    request_id: str
    timestamp: str
    decision: Action
    finding_count: int
    rule_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    duration_ms: float
    policy_version: int


class PrivacyDatabase:
    """Restrictive local SQLite store for metadata-only inspection summaries."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        descriptor = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(descriptor)
        os.chmod(self.path, 0o600)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS inspection_summaries (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN ('allow', 'redact', 'block')),
                    finding_count INTEGER NOT NULL CHECK(finding_count >= 0),
                    rule_ids_json TEXT NOT NULL,
                    model_ids_json TEXT NOT NULL,
                    duration_ms REAL NOT NULL CHECK(duration_ms >= 0),
                    policy_version INTEGER NOT NULL CHECK(policy_version > 0)
                )
                """
            )

    def usable(self) -> bool:
        try:
            self.initialize()
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except (OSError, sqlite3.Error):
            return False
        return True

    def write(self, summary: InspectionSummary) -> None:
        self.initialize()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO inspection_summaries (
                    request_id, timestamp, decision, finding_count, rule_ids_json,
                    model_ids_json, duration_ms, policy_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.request_id,
                    summary.timestamp,
                    summary.decision.value,
                    summary.finding_count,
                    json.dumps(summary.rule_ids, separators=(",", ":")),
                    json.dumps(summary.model_ids, separators=(",", ":")),
                    summary.duration_ms,
                    summary.policy_version,
                ),
            )
            connection.execute(
                """
                DELETE FROM inspection_summaries
                WHERE request_id NOT IN (
                    SELECT request_id FROM inspection_summaries
                    ORDER BY timestamp DESC
                    LIMIT 1000
                )
                """
            )

    def recent(self, limit: int = 20) -> list[InspectionSummary]:
        if not 1 <= limit <= 100:
            raise ValueError("history limit must be between 1 and 100")
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT request_id, timestamp, decision, finding_count, rule_ids_json,
                       model_ids_json, duration_ms, policy_version
                FROM inspection_summaries
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            InspectionSummary(
                request_id=row[0],
                timestamp=row[1],
                decision=Action(row[2]),
                finding_count=row[3],
                rule_ids=tuple(json.loads(row[4])),
                model_ids=tuple(json.loads(row[5])),
                duration_ms=row[6],
                policy_version=row[7],
            )
            for row in rows
        ]

    def clear(self) -> int:
        self.initialize()
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM inspection_summaries")
            return cursor.rowcount

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA temp_store = MEMORY")
        return connection


def make_summary(
    *,
    request_id: str,
    decision: Action,
    finding_count: int,
    rule_ids: tuple[str, ...],
    model_ids: tuple[str, ...],
    duration_ms: float,
    policy_version: int,
) -> InspectionSummary:
    return InspectionSummary(
        request_id=request_id,
        timestamp=datetime.now(UTC).isoformat(),
        decision=decision,
        finding_count=finding_count,
        rule_ids=rule_ids,
        model_ids=model_ids,
        duration_ms=duration_ms,
        policy_version=policy_version,
    )
