import os
import sqlite3
from pathlib import Path

from ai_firewall.models import Action
from ai_firewall.privacy.database import PrivacyDatabase, make_summary


def test_database_stores_only_allowlisted_metadata(tmp_path: Path) -> None:
    path = tmp_path / "private" / "privacy.db"
    database = PrivacyDatabase(path)
    source_marker = "SYNTHETIC_SOURCE_MUST_NOT_PERSIST"

    database.write(
        make_summary(
            request_id="00000000-0000-4000-8000-000000000001",
            decision=Action.BLOCK,
            finding_count=1,
            rule_ids=("synthetic_rule",),
            model_ids=(),
            duration_ms=1.25,
            policy_version=1,
        )
    )

    assert source_marker.encode() not in path.read_bytes()
    summary = database.recent()[0]
    assert summary.decision == Action.BLOCK
    assert summary.rule_ids == ("synthetic_rule",)
    assert os.stat(path).st_mode & 0o777 == 0o600
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(inspection_summaries)")}
    assert columns == {
        "request_id",
        "timestamp",
        "decision",
        "finding_count",
        "rule_ids_json",
        "model_ids_json",
        "duration_ms",
        "policy_version",
    }


def test_database_history_can_be_cleared(tmp_path: Path) -> None:
    database = PrivacyDatabase(tmp_path / "privacy.db")
    database.write(
        make_summary(
            request_id="00000000-0000-4000-8000-000000000002",
            decision=Action.BLOCK,
            finding_count=0,
            rule_ids=(),
            model_ids=(),
            duration_ms=0.5,
            policy_version=1,
        )
    )

    assert database.clear() == 1
    assert database.recent() == []
