import math
import re
from dataclasses import dataclass
from typing import Any

from .models import Action, Finding, ScanResponse
from .policy import Policy, Rule

ACTION_RANK = {Action.ALLOW: 0, Action.REDACT: 1, Action.BLOCK: 2}
MAX_SCAN_DEPTH = 64
MAX_SCAN_NODES = 50_000
SENSITIVE_FIELD_NAME_PATTERN = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|secret|password|token|credentials?|private[_-]?key)(?:$|[_-])"
)


@dataclass
class _ScanState:
    findings: list[Finding]
    active_containers: set[int]
    nodes_seen: int = 0
    budget_exhausted: bool = False


@dataclass(frozen=True)
class _RedactionSpan:
    start: int
    end: int
    rule_id: str


def _valid_luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _is_valid(rule: Rule, value: str) -> bool:
    return rule.validator != "luhn" or _valid_luhn(value)


def _redact_spans(text: str, spans: list[_RedactionSpan]) -> str:
    if not spans:
        return text

    ordered = sorted(spans, key=lambda span: (span.start, span.end, span.rule_id))
    merged: list[tuple[int, int, set[str]]] = []
    for span in ordered:
        if merged and span.start <= merged[-1][1]:
            start, end, rule_ids = merged[-1]
            rule_ids.add(span.rule_id)
            merged[-1] = (start, max(end, span.end), rule_ids)
        else:
            merged.append((span.start, span.end, {span.rule_id}))

    pieces: list[str] = []
    cursor = 0
    for start, end, rule_ids in merged:
        pieces.append(text[cursor:start])
        marker = "|".join(sorted(rule_ids))
        pieces.append(f"[REDACTED:{marker}]")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _scan_text(text: str, path: str, policy: Policy) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    redactions: list[_RedactionSpan] = []
    for rule in policy.rules:
        try:
            matches = [
                match
                for match in rule.pattern.finditer(text)
                if _is_valid(rule, match.group())
            ]
        except Exception:  # noqa: BLE001 - detector plugins must fail closed
            findings.append(_internal_block("detector_failure", path, "critical"))
            continue
        if not matches:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                action=rule.action,
                path=path,
                count=len(matches),
            )
        )
        if rule.action == Action.REDACT:
            redactions.extend(
                _RedactionSpan(match.start(), match.end(), rule.id) for match in matches
            )
    return _redact_spans(text, redactions), findings


def _internal_block(rule_id: str, path: str, severity: str = "high") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        action=Action.BLOCK,
        path=path,
    )


def _promote_to_block(findings: list[Finding]) -> list[Finding]:
    return [
        finding.model_copy(update={"action": Action.BLOCK})
        if finding.action == Action.REDACT
        else finding
        for finding in findings
    ]


def _is_sensitive_field_name(name: str) -> bool:
    snake_case = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    return SENSITIVE_FIELD_NAME_PATTERN.search(snake_case) is not None


def scan_payload(payload: Any, policy: Policy) -> ScanResponse:
    state = _ScanState(findings=[], active_containers=set())

    def walk(value: Any, path: str, depth: int) -> Any:
        if depth > MAX_SCAN_DEPTH:
            state.findings.append(_internal_block("inspection_depth_exceeded", path, "critical"))
            return None

        state.nodes_seen += 1
        if state.nodes_seen > MAX_SCAN_NODES:
            if not state.budget_exhausted:
                state.findings.append(
                    _internal_block("inspection_node_limit_exceeded", path, "critical")
                )
                state.budget_exhausted = True
            return None

        if isinstance(value, str):
            result, detected = _scan_text(value, path, policy)
            state.findings.extend(detected)
            return result

        if value is None or isinstance(value, bool):
            return value

        if isinstance(value, int):
            _ignored, detected = _scan_text(str(value), path, policy)
            state.findings.extend(_promote_to_block(detected))
            return value

        if isinstance(value, float):
            if not math.isfinite(value):
                state.findings.append(_internal_block("unsupported_value", path))
                return None
            _ignored, detected = _scan_text(str(value), path, policy)
            state.findings.extend(_promote_to_block(detected))
            return value

        if isinstance(value, (list, dict)):
            identity = id(value)
            if identity in state.active_containers:
                state.findings.append(_internal_block("cyclic_value", path, "critical"))
                return None
            state.active_containers.add(identity)
            try:
                if isinstance(value, list):
                    return [walk(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]

                result: dict[str, Any] = {}
                for index, (key, item) in enumerate(value.items()):
                    key_path = f"{path}.key[{index}]"
                    value_path = f"{path}.value[{index}]"
                    if not isinstance(key, str):
                        state.findings.append(_internal_block("unsupported_mapping_key", key_path))
                        continue
                    state.nodes_seen += 1
                    if state.nodes_seen > MAX_SCAN_NODES:
                        if not state.budget_exhausted:
                            state.findings.append(
                                _internal_block(
                                    "inspection_node_limit_exceeded", key_path, "critical"
                                )
                            )
                            state.budget_exhausted = True
                        break
                    _ignored, key_findings = _scan_text(key, key_path, policy)
                    state.findings.extend(_promote_to_block(key_findings))
                    if _is_sensitive_field_name(key):
                        state.findings.append(
                            _internal_block("sensitive_field_name", key_path, "critical")
                        )
                    result[key] = walk(item, value_path, depth + 1)
                return result
            finally:
                state.active_containers.remove(identity)

        state.findings.append(_internal_block("unsupported_value", path))
        return None

    sanitized = walk(payload, "$", 0)
    if not state.findings:
        decision = policy.default_action
    else:
        decision = max(
            (finding.action for finding in state.findings), key=ACTION_RANK.__getitem__
        )
    return ScanResponse(
        decision=decision,
        payload=None if decision == Action.BLOCK else sanitized,
        findings=state.findings,
    )
