from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from time import monotonic
from typing import Any
from uuid import uuid4

from ai_firewall.audit import write_audit_event
from ai_firewall.models import Action, Finding, ScanResponse
from ai_firewall.policy import Policy
from ai_firewall.scanner import scan_payload

from .database import InspectionSummary, PrivacyDatabase, make_summary
from .events import EventEmitter, EventSink, EventStatus, PrivacyPhase
from .models import LocalModelRegistry, ModelExecutionError


@dataclass(frozen=True, slots=True)
class InspectionOutcome:
    request_id: str
    response: ScanResponse


class PrivacyOrchestrator:
    """Run the bounded local privacy graph without persisting source content."""

    def __init__(
        self,
        *,
        policy: Policy,
        audit_path,
        database: PrivacyDatabase,
        models: LocalModelRegistry,
    ) -> None:
        self.policy = policy
        self.audit_path = audit_path
        self.database = database
        self.models = models

    async def inspect(self, payload: Any, sink: EventSink | None = None) -> InspectionOutcome:
        request_id = str(uuid4())
        emitter = EventEmitter(request_id, sink)
        started = monotonic()
        await emitter.emit(
            PrivacyPhase.RECEIVED,
            EventStatus.COMPLETED,
            {"policy_version": self.policy.version},
        )

        await emitter.emit(PrivacyPhase.DETERMINISTIC, EventStatus.STARTED)
        result = await asyncio.to_thread(scan_payload, payload, self.policy)
        await emitter.emit(
            PrivacyPhase.DETERMINISTIC,
            EventStatus.COMPLETED,
            _finding_metadata(result),
        )

        if result.decision == Action.BLOCK:
            await emitter.emit(
                PrivacyPhase.LOCAL_MODEL,
                EventStatus.SKIPPED,
                {"model_count": len(self.models.model_ids)},
            )
        else:
            result = await self._apply_models(payload, result, emitter)

        result = await self._residual_scan(result, emitter)
        duration_ms = round((monotonic() - started) * 1000, 3)
        result = await self._persist(result, request_id, duration_ms, emitter)
        await emitter.emit(
            PrivacyPhase.DECISION,
            EventStatus.COMPLETED,
            {"decision": result.decision.value, **_finding_metadata(result)},
        )
        await emitter.emit(
            PrivacyPhase.COMPLETE,
            EventStatus.COMPLETED,
            {"decision": result.decision.value, "duration_ms": duration_ms},
        )
        return InspectionOutcome(request_id=request_id, response=result)

    async def _apply_models(
        self,
        payload: Any,
        result: ScanResponse,
        emitter: EventEmitter,
    ) -> ScanResponse:
        if not self.models.model_ids:
            await emitter.emit(
                PrivacyPhase.LOCAL_MODEL,
                EventStatus.SKIPPED,
                {"model_count": 0},
            )
            return result
        await emitter.emit(
            PrivacyPhase.LOCAL_MODEL,
            EventStatus.STARTED,
            {"model_count": len(self.models.model_ids), "model_ids": ",".join(self.models.model_ids)},
        )
        try:
            model_findings = await self.models.inspect(payload)
        except ModelExecutionError:
            model_findings = [_block_finding("mandatory_model_failure")]
            await emitter.emit(PrivacyPhase.LOCAL_MODEL, EventStatus.FAILED)
        else:
            await emitter.emit(
                PrivacyPhase.LOCAL_MODEL,
                EventStatus.COMPLETED,
                {"finding_count": sum(finding.count for finding in model_findings)},
            )
        if model_findings:
            return ScanResponse(
                decision=Action.BLOCK,
                payload=None,
                findings=[*result.findings, *model_findings],
            )
        return result

    async def _residual_scan(
        self, result: ScanResponse, emitter: EventEmitter
    ) -> ScanResponse:
        if result.decision != Action.REDACT or result.payload is None:
            await emitter.emit(
                PrivacyPhase.RESIDUAL,
                EventStatus.SKIPPED,
                {"residual_pass": result.decision == Action.BLOCK},
            )
            return result
        await emitter.emit(PrivacyPhase.RESIDUAL, EventStatus.STARTED)
        try:
            serialized = json.dumps(
                result.payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            residual_policy = Policy(
                version=self.policy.version,
                default_action=Action.ALLOW,
                allowed_hosts=self.policy.allowed_hosts,
                rules=self.policy.rules,
            )
            residual = await asyncio.to_thread(scan_payload, serialized, residual_policy)
        except (TypeError, ValueError):
            residual = ScanResponse(
                decision=Action.BLOCK,
                payload=None,
                findings=[_block_finding("residual_serialization_failure")],
            )
        if residual.findings or residual.decision == Action.BLOCK:
            blocked = ScanResponse(
                decision=Action.BLOCK,
                payload=None,
                findings=[*result.findings, _block_finding("residual_sensitive_data")],
            )
            await emitter.emit(PrivacyPhase.RESIDUAL, EventStatus.FAILED, {"residual_pass": False})
            return blocked
        await emitter.emit(PrivacyPhase.RESIDUAL, EventStatus.COMPLETED, {"residual_pass": True})
        return result

    async def _persist(
        self,
        result: ScanResponse,
        request_id: str,
        duration_ms: float,
        emitter: EventEmitter,
    ) -> ScanResponse:
        await emitter.emit(PrivacyPhase.PERSISTENCE, EventStatus.STARTED)
        try:
            await asyncio.to_thread(
                self.database.write,
                self._summary(result, request_id, duration_ms),
            )
            await asyncio.to_thread(write_audit_event, self.audit_path, result)
        except Exception:  # noqa: BLE001 - persistence dependencies must fail closed
            blocked = ScanResponse(
                decision=Action.BLOCK,
                payload=None,
                findings=[*result.findings, _block_finding("privacy_persistence_failure")],
            )
            repaired = await self._repair_blocked_summary(
                blocked,
                request_id,
                duration_ms,
            )
            await emitter.emit(
                PrivacyPhase.PERSISTENCE,
                EventStatus.FAILED,
                {"persistence": "failed" if repaired else "failed_unrecorded"},
            )
            return blocked
        await emitter.emit(
            PrivacyPhase.PERSISTENCE,
            EventStatus.COMPLETED,
            {"persistence": "metadata_only"},
        )
        return result

    async def _repair_blocked_summary(
        self,
        blocked: ScanResponse,
        request_id: str,
        duration_ms: float,
    ) -> bool:
        try:
            await asyncio.to_thread(
                self.database.write,
                self._summary(blocked, request_id, duration_ms),
            )
        except Exception:  # noqa: BLE001 - best-effort repair after fail-closed decision
            return False
        return True

    def _summary(
        self,
        result: ScanResponse,
        request_id: str,
        duration_ms: float,
    ) -> InspectionSummary:
        return make_summary(
            request_id=request_id,
            decision=result.decision,
            finding_count=sum(finding.count for finding in result.findings),
            rule_ids=tuple(sorted({finding.rule_id for finding in result.findings})),
            model_ids=self.models.model_ids,
            duration_ms=duration_ms,
            policy_version=self.policy.version,
        )

    def topology(self) -> dict[str, Any]:
        return {
            "mode": "local_only",
            "payload_persistence": "disabled",
            "forwarding": "disabled",
            "agents": [
                {"id": "request_gate", "action": "authenticate_and_bound"},
                {"id": "deterministic_detector", "action": "detect_and_redact"},
                {"id": "local_model_gate", "action": "validate_pinned_structured_spans"},
                {"id": "residual_guard", "action": "rescan_serialized_output"},
                {"id": "decision_agent", "action": "select_strictest_action"},
                {"id": "metadata_writer", "action": "persist_metadata_only"},
            ],
            "models": self.models.topology(),
            "graph": [
                ["request_gate", "deterministic_detector"],
                ["deterministic_detector", "local_model_gate"],
                ["local_model_gate", "residual_guard"],
                ["residual_guard", "metadata_writer"],
                ["metadata_writer", "decision_agent"],
            ],
            "bounded_loops": [
                {
                    "id": "residual_rescan",
                    "max_iterations": 1,
                    "failure_action": "block",
                }
            ],
            "events": [phase.value for phase in PrivacyPhase],
        }


def _finding_metadata(result: ScanResponse) -> dict[str, str | int]:
    return {
        "finding_count": sum(finding.count for finding in result.findings),
        "rule_ids": ",".join(sorted({finding.rule_id for finding in result.findings})),
    }


def _block_finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity="critical",
        action=Action.BLOCK,
        path="$",
    )
