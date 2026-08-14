import json
import re
from pathlib import Path

import pytest

from ai_firewall.models import Action
from ai_firewall.policy import Policy, Rule, load_policy
from ai_firewall.privacy import LocalModelRegistry, PrivacyDatabase, PrivacyOrchestrator
from ai_firewall.privacy.models import ModelManifest

POLICY = load_policy(Path("config/policy.yaml"))
EMPTY_MODELS = LocalModelRegistry(ModelManifest(version=1, models=()))


def _orchestrator(tmp_path: Path, policy: Policy = POLICY) -> PrivacyOrchestrator:
    return PrivacyOrchestrator(
        policy=policy,
        audit_path=tmp_path / "audit.jsonl",
        database=PrivacyDatabase(tmp_path / "privacy.db"),
        models=EMPTY_MODELS,
    )


@pytest.mark.asyncio
async def test_events_and_persistence_never_contain_source_content(tmp_path: Path) -> None:
    source = "Contact synthetic.user@example.com"
    events = []

    async def collect(event) -> None:
        events.append(event)

    outcome = await _orchestrator(tmp_path).inspect({"prompt": source}, collect)

    assert outcome.response.decision == Action.REDACT
    assert all(source not in event.model_dump_json() for event in events)
    assert source.encode() not in (tmp_path / "privacy.db").read_bytes()
    assert source not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))


@pytest.mark.asyncio
async def test_residual_serialized_output_is_blocked(tmp_path: Path) -> None:
    policy = Policy(
        version=1,
        default_action=Action.BLOCK,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=(
            Rule(
                id="synthetic_redaction",
                description="Synthetic redaction",
                pattern=re.compile("SYNTHETIC_SOURCE"),
                action=Action.REDACT,
                severity="high",
            ),
            Rule(
                id="redaction_marker_guard",
                description="Synthetic residual guard",
                pattern=re.compile("REDACTED"),
                action=Action.BLOCK,
                severity="critical",
            ),
        ),
    )

    outcome = await _orchestrator(tmp_path, policy).inspect("SYNTHETIC_SOURCE")

    assert outcome.response.decision == Action.BLOCK
    assert outcome.response.payload is None
    assert any(finding.rule_id == "residual_sensitive_data" for finding in outcome.response.findings)


@pytest.mark.asyncio
async def test_database_failure_blocks_without_returning_payload(tmp_path: Path, monkeypatch) -> None:
    orchestrator = _orchestrator(tmp_path)

    def fail_write(summary) -> None:
        raise OSError("synthetic storage failure")

    monkeypatch.setattr(orchestrator.database, "write", fail_write)
    outcome = await orchestrator.inspect("synthetic.user@example.com")

    assert outcome.response.decision == Action.BLOCK
    assert outcome.response.payload is None
    assert any(
        finding.rule_id == "privacy_persistence_failure"
        for finding in outcome.response.findings
    )
    assert "synthetic.user@example.com" not in json.dumps(outcome.response.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_audit_failure_repairs_database_summary_to_block(
    tmp_path: Path, monkeypatch
) -> None:
    orchestrator = _orchestrator(tmp_path)

    def fail_audit(path, result) -> None:
        raise OSError("synthetic audit failure")

    monkeypatch.setattr(
        "ai_firewall.privacy.orchestrator.write_audit_event",
        fail_audit,
    )
    outcome = await orchestrator.inspect("synthetic.user@example.com")
    stored = orchestrator.database.recent(limit=1)

    assert outcome.response.decision == Action.BLOCK
    assert outcome.response.payload is None
    assert len(stored) == 1
    assert stored[0].request_id == outcome.request_id
    assert stored[0].decision == Action.BLOCK
    assert "privacy_persistence_failure" in stored[0].rule_ids
    assert b"synthetic.user@example.com" not in orchestrator.database.path.read_bytes()
