import re
from pathlib import Path

from ai_firewall.models import Action
from ai_firewall.policy import Policy, Rule, load_policy
from ai_firewall.scanner import scan_payload

POLICY = load_policy(Path("config/policy.yaml"))


def test_default_action_blocks_unmatched_payload() -> None:
    result = scan_payload({"messages": [{"content": "Summarize this public text."}]}, POLICY)
    assert result.decision == Action.BLOCK
    assert result.payload is None
    assert result.findings == []


def test_default_action_applies_to_empty_inputs() -> None:
    for payload in (None, "", [], {}):
        result = scan_payload(payload, POLICY)
        assert result.decision == Action.BLOCK
        assert result.payload is None
        assert result.findings == []


def test_allow_default_allows_fully_inspected_unmatched_input() -> None:
    policy = Policy(
        version=1,
        default_action=Action.ALLOW,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=POLICY.rules,
    )
    result = scan_payload({"count": 1}, policy)
    assert result.decision == Action.ALLOW
    assert result.payload == {"count": 1}
    assert result.findings == []


def test_redacts_email_recursively() -> None:
    result = scan_payload({"messages": [{"content": "Contact alice@example.com"}]}, POLICY)
    assert result.decision == Action.REDACT
    assert result.payload["messages"][0]["content"] == "Contact [REDACTED:email]"


def test_blocks_private_key_without_returning_payload() -> None:
    result = scan_payload({"prompt": "-----BEGIN PRIVATE KEY-----"}, POLICY)
    assert result.decision == Action.BLOCK
    assert result.payload is None


def test_luhn_rule_ignores_invalid_number() -> None:
    result = scan_payload({"prompt": "Reference 1234 5678 9012 3456"}, POLICY)
    assert all(finding.rule_id != "payment_card" for finding in result.findings)


def test_luhn_rule_blocks_valid_test_card() -> None:
    result = scan_payload({"prompt": "Card 4111 1111 1111 1111"}, POLICY)
    assert result.decision == Action.BLOCK


def test_benign_string_does_not_authorize_sensitive_numeric_value() -> None:
    result = scan_payload(
        {"model": "synthetic-model", "payment_reference": 4111111111111111}, POLICY
    )
    assert result.decision == Action.BLOCK
    assert result.payload is None
    assert any(finding.rule_id == "payment_card" for finding in result.findings)


def test_inspects_mapping_keys_and_blocks_ambiguous_redaction() -> None:
    result = scan_payload({"synthetic.user@example.com": "ordinary"}, POLICY)
    assert result.decision == Action.BLOCK
    assert result.payload is None
    finding = next(finding for finding in result.findings if finding.rule_id == "email")
    assert finding.action == Action.BLOCK
    assert finding.path == "$.key[0]"


def test_inspects_mapping_keys_for_block_rules() -> None:
    result = scan_payload({"password=syntheticsecretvalue": "ordinary"}, POLICY)
    assert result.decision == Action.BLOCK
    assert any(finding.rule_id == "generic_secret" for finding in result.findings)


def test_blocks_exact_sensitive_field_name_with_separate_value() -> None:
    result = scan_payload(
        {"input": "public", "api_key": "SYNTHETIC_VALUE_123456"}, POLICY
    )
    assert result.decision == Action.BLOCK
    assert result.payload is None
    assert any(finding.rule_id == "sensitive_field_name" for finding in result.findings)


def test_blocks_common_structured_secret_field_aliases() -> None:
    for field_name in (
        "client_secret",
        "refresh_token",
        "accessToken",
        "apiKey",
        "private-key",
        "credentials",
    ):
        result = scan_payload(
            {"input": "public", field_name: "SYNTHETIC_VALUE_123456"}, POLICY
        )
        assert result.decision == Action.BLOCK, field_name
        assert any(finding.rule_id == "sensitive_field_name" for finding in result.findings)


def test_sensitive_field_guard_does_not_block_benign_token_settings() -> None:
    policy = Policy(
        version=1,
        default_action=Action.ALLOW,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=POLICY.rules,
    )
    result = scan_payload({"input": "public", "max_tokens": 250}, policy)
    assert result.decision == Action.ALLOW
    assert result.payload == {"input": "public", "max_tokens": 250}


def test_detector_failure_blocks_without_exposing_exception(monkeypatch) -> None:
    def fail_detector(rule: Rule, value: str) -> bool:
        raise RuntimeError("synthetic detector internals")

    monkeypatch.setattr("ai_firewall.scanner._is_valid", fail_detector)
    result = scan_payload("alice@example.com", POLICY)

    assert result.decision == Action.BLOCK
    assert result.payload is None
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "detector_failure"
    assert result.findings[0].severity == "critical"


def test_detects_every_rule_against_immutable_original_text() -> None:
    policy = Policy(
        version=1,
        default_action=Action.BLOCK,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=(
            Rule(
                id="prefix",
                description="Synthetic prefix",
                pattern=re.compile(r"token="),
                action=Action.REDACT,
                severity="medium",
            ),
            Rule(
                id="synthetic_token",
                description="Synthetic token",
                pattern=re.compile(r"token=[A-Z]{12,}"),
                action=Action.BLOCK,
                severity="high",
            ),
        ),
    )
    result = scan_payload("token=SYNTHETICVALUE", policy)
    assert result.decision == Action.BLOCK
    assert {finding.rule_id for finding in result.findings} == {"prefix", "synthetic_token"}


def test_redacts_only_validator_approved_spans() -> None:
    policy = Policy(
        version=1,
        default_action=Action.BLOCK,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=(
            Rule(
                id="validated_number",
                description="Synthetic validated number",
                pattern=re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
                action=Action.REDACT,
                severity="high",
                validator="luhn",
            ),
        ),
    )
    result = scan_payload("Valid 4111 1111 1111 1111 invalid 1234 5678 9012 3456", policy)
    assert result.decision == Action.REDACT
    assert result.payload == "Valid [REDACTED:validated_number]invalid 1234 5678 9012 3456"


def test_replacement_never_expands_backreferences_from_rule_id() -> None:
    policy = Policy(
        version=1,
        default_action=Action.BLOCK,
        allowed_hosts=frozenset({"api.example.test"}),
        rules=(
            Rule(
                id=r"leak_\g<0>",
                description="Direct construction regression",
                pattern=re.compile("SYNTHETICSECRET"),
                action=Action.REDACT,
                severity="high",
            ),
        ),
    )
    result = scan_payload("SYNTHETICSECRET", policy)
    assert result.decision == Action.REDACT
    assert result.payload == r"[REDACTED:leak_\g<0>]"
    assert "SYNTHETICSECRET" not in result.payload


def test_blocks_unsupported_and_nonfinite_values() -> None:
    for payload in ({"value": {1, 2}}, {"value": float("nan")}, {"value": float("inf")}):
        result = scan_payload(payload, POLICY)
        assert result.decision == Action.BLOCK
        assert result.payload is None
        assert any(finding.rule_id == "unsupported_value" for finding in result.findings)


def test_blocks_non_string_mapping_keys() -> None:
    result = scan_payload({1: "ordinary"}, POLICY)
    assert result.decision == Action.BLOCK
    assert any(finding.rule_id == "unsupported_mapping_key" for finding in result.findings)


def test_depth_500_returns_block_finding_instead_of_recursion_error() -> None:
    payload: object = "ordinary"
    for _ in range(500):
        payload = [payload]
    result = scan_payload(payload, POLICY)
    assert result.decision == Action.BLOCK
    assert result.payload is None
    assert any(finding.rule_id == "inspection_depth_exceeded" for finding in result.findings)


def test_blocks_cycles_in_direct_python_input() -> None:
    payload: list[object] = []
    payload.append(payload)
    result = scan_payload(payload, POLICY)
    assert result.decision == Action.BLOCK
    assert any(finding.rule_id == "cyclic_value" for finding in result.findings)


def test_node_budget_returns_block_finding(monkeypatch) -> None:
    monkeypatch.setattr("ai_firewall.scanner.MAX_SCAN_NODES", 3)
    result = scan_payload(["one", "two", "three", "four"], POLICY)
    assert result.decision == Action.BLOCK
    assert any(finding.rule_id == "inspection_node_limit_exceeded" for finding in result.findings)
