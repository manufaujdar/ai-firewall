from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from ai_firewall.models import Action
from ai_firewall.policy import PolicyValidationError, load_policy


def _valid_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "default_action": "block",
        "allowed_hosts": ["api.example.test"],
        "rules": [
            {
                "id": "synthetic_email",
                "description": "Redact a synthetic email-shaped value",
                "pattern": r"\b[A-Za-z]+@example\.test\b",
                "action": "redact",
                "severity": "medium",
            }
        ],
    }


def _write_policy(tmp_path: Path, policy: Any) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


def test_loads_complete_policy(tmp_path: Path) -> None:
    policy = load_policy(_write_policy(tmp_path, _valid_policy()))
    assert policy.default_action == Action.BLOCK
    assert policy.allowed_hosts == frozenset({"api.example.test"})
    assert policy.rules[0].action == Action.REDACT


@pytest.mark.parametrize("missing", ["version", "default_action", "allowed_hosts", "rules"])
def test_rejects_missing_security_critical_fields(tmp_path: Path, missing: str) -> None:
    raw = _valid_policy()
    del raw[missing]
    with pytest.raises(PolicyValidationError):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize("field", ["allowed_hosts", "rules"])
def test_rejects_empty_security_critical_lists(tmp_path: Path, field: str) -> None:
    raw = _valid_policy()
    raw[field] = []
    with pytest.raises(PolicyValidationError):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize("document", [None, "", [], "not a mapping"])
def test_rejects_empty_or_malformed_document(tmp_path: Path, document: Any) -> None:
    with pytest.raises(PolicyValidationError):
        load_policy(_write_policy(tmp_path, document))


@pytest.mark.parametrize("field", ["id", "description", "pattern", "action", "severity"])
def test_rejects_missing_or_empty_rule_fields(tmp_path: Path, field: str) -> None:
    for value in (None, ""):
        raw = _valid_policy()
        if value is None:
            del raw["rules"][0][field]
        else:
            raw["rules"][0][field] = value
        with pytest.raises(PolicyValidationError):
            load_policy(_write_policy(tmp_path, raw))


def test_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    raw = _valid_policy()
    raw["rules"].append(deepcopy(raw["rules"][0]))
    with pytest.raises(PolicyValidationError, match="unique"):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("action", "permit", "unknown action"),
        ("validator", "remote_lookup", "unknown validator"),
        ("severity", "urgent", "unknown value"),
    ],
)
def test_rejects_unknown_rule_enums(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    raw = _valid_policy()
    raw["rules"][0][field] = value
    with pytest.raises(PolicyValidationError, match=message):
        load_policy(_write_policy(tmp_path, raw))


def test_rejects_unknown_default_action(tmp_path: Path) -> None:
    raw = _valid_policy()
    raw["default_action"] = "permit"
    with pytest.raises(PolicyValidationError, match="unknown action"):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize("action", ["allow", "redact"])
def test_policy_v1_requires_default_block(tmp_path: Path, action: str) -> None:
    raw = _valid_policy()
    raw["default_action"] = action
    with pytest.raises(PolicyValidationError, match="must be block"):
        load_policy(_write_policy(tmp_path, raw))


def test_rejects_allow_rule(tmp_path: Path) -> None:
    raw = _valid_policy()
    raw["rules"][0]["action"] = "allow"
    with pytest.raises(PolicyValidationError, match="redact or block"):
        load_policy(_write_policy(tmp_path, raw))


def test_rejects_invalid_regex(tmp_path: Path) -> None:
    raw = _valid_policy()
    raw["rules"][0]["pattern"] = "[unterminated"
    with pytest.raises(PolicyValidationError, match="regular expression"):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize("host", ["", "https://api.example.test", "*.example.test", "host:443"])
def test_rejects_malformed_allowed_host(tmp_path: Path, host: str) -> None:
    raw = _valid_policy()
    raw["allowed_hosts"] = [host]
    with pytest.raises(PolicyValidationError):
        load_policy(_write_policy(tmp_path, raw))


def test_rejects_unknown_fields_to_catch_policy_typos(tmp_path: Path) -> None:
    raw = _valid_policy()
    raw["default_aciton"] = "allow"
    with pytest.raises(PolicyValidationError, match="unknown field"):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize(
    "rule_id",
    ["Uppercase", "contains-hyphen", "contains space", r"leak_\g<0>", "a" * 65, "_prefix"],
)
def test_rejects_unsafe_rule_ids(tmp_path: Path, rule_id: str) -> None:
    raw = _valid_policy()
    raw["rules"][0]["id"] = rule_id
    with pytest.raises(PolicyValidationError, match="must match"):
        load_policy(_write_policy(tmp_path, raw))


@pytest.mark.parametrize(
    "document",
    [
        """version: 1
default_action: block
default_action: allow
allowed_hosts: [api.example.test]
rules:
  - id: synthetic
    description: Synthetic rule
    pattern: synthetic
    action: block
    severity: high
""",
        """version: 1
default_action: block
allowed_hosts: [api.example.test]
rules:
  - id: synthetic
    id: overwritten
    description: Synthetic rule
    pattern: synthetic
    action: block
    severity: high
""",
    ],
)
def test_rejects_duplicate_yaml_keys_recursively(tmp_path: Path, document: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="duplicate mapping key"):
        load_policy(path)


def test_rejects_missing_policy_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyValidationError, match="unable to load"):
        load_policy(tmp_path / "missing.yaml")
