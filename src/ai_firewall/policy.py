import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode

from .models import Action

SUPPORTED_POLICY_VERSION = 1
SUPPORTED_VALIDATORS = frozenset({"luhn"})
SUPPORTED_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
POLICY_FIELDS = frozenset({"version", "default_action", "allowed_hosts", "rules"})
RULE_FIELDS = frozenset(
    {"id", "description", "pattern", "action", "severity", "validator"}
)
HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class PolicyValidationError(ValueError):
    """Raised when a policy cannot be loaded safely."""


class _DuplicateKeyError(yaml.YAMLError):
    """Raised by the policy-only YAML loader for duplicate mapping keys."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys at every mapping depth."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise _DuplicateKeyError(f"duplicate mapping key {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    action: Action
    severity: str
    validator: str | None = None


@dataclass(frozen=True)
class Policy:
    version: int
    default_action: Action
    allowed_hosts: frozenset[str]
    rules: tuple[Rule, ...]


def _require_mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyValidationError(f"{location} must be a mapping")
    return value


def _require_non_empty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyValidationError(f"{location} must be a non-empty string")
    return value.strip()


def _reject_unknown_fields(item: dict[str, Any], allowed: frozenset[str], location: str) -> None:
    unknown = set(item) - allowed
    if unknown:
        names = ", ".join(sorted(str(field) for field in unknown))
        raise PolicyValidationError(f"{location} contains unknown field(s): {names}")


def _parse_action(value: Any, location: str) -> Action:
    action = _require_non_empty_string(value, location)
    try:
        return Action(action)
    except ValueError as exc:
        raise PolicyValidationError(f"{location} has unknown action {action!r}") from exc


def _parse_host(value: Any, index: int) -> str:
    host = _require_non_empty_string(value, f"allowed_hosts[{index}]").lower()
    if not HOST_PATTERN.fullmatch(host):
        raise PolicyValidationError(
            f"allowed_hosts[{index}] must be a DNS hostname without a scheme, port, or wildcard"
        )
    return host


def _parse_rule(value: Any, index: int) -> Rule:
    location = f"rules[{index}]"
    item = _require_mapping(value, location)
    _reject_unknown_fields(item, RULE_FIELDS, location)

    rule_id = _require_non_empty_string(item.get("id"), f"{location}.id")
    if RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise PolicyValidationError(
            f"{location}.id must match ^[a-z][a-z0-9_]{{0,63}}$"
        )
    description = _require_non_empty_string(item.get("description"), f"{location}.description")
    pattern_text = _require_non_empty_string(item.get("pattern"), f"{location}.pattern")
    action = _parse_action(item.get("action"), f"{location}.action")
    if action not in {Action.REDACT, Action.BLOCK}:
        raise PolicyValidationError(f"{location}.action must be redact or block")
    severity = _require_non_empty_string(item.get("severity"), f"{location}.severity")
    if severity not in SUPPORTED_SEVERITIES:
        raise PolicyValidationError(f"{location}.severity has unknown value {severity!r}")

    validator_value = item.get("validator")
    validator = None
    if validator_value is not None:
        validator = _require_non_empty_string(validator_value, f"{location}.validator")
        if validator not in SUPPORTED_VALIDATORS:
            raise PolicyValidationError(
                f"{location}.validator has unknown validator {validator!r}"
            )

    try:
        pattern = re.compile(pattern_text)
    except re.error as exc:
        raise PolicyValidationError(f"{location}.pattern is not a valid regular expression") from exc

    return Rule(
        id=rule_id,
        description=description,
        pattern=pattern,
        action=action,
        severity=severity,
        validator=validator,
    )


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeySafeLoader)
    except _DuplicateKeyError as exc:
        raise PolicyValidationError("policy contains a duplicate mapping key") from exc
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PolicyValidationError(f"unable to load policy from {path}") from exc

    document = _require_mapping(raw, "policy")
    _reject_unknown_fields(document, POLICY_FIELDS, "policy")

    version = document.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise PolicyValidationError("version must be an integer")
    if version != SUPPORTED_POLICY_VERSION:
        raise PolicyValidationError(f"unsupported policy version {version!r}")

    default_action = _parse_action(document.get("default_action"), "default_action")
    if default_action != Action.BLOCK:
        raise PolicyValidationError("default_action must be block for policy version 1")

    allowed_hosts_value = document.get("allowed_hosts")
    if not isinstance(allowed_hosts_value, list) or not allowed_hosts_value:
        raise PolicyValidationError("allowed_hosts must be a non-empty list")
    hosts = tuple(_parse_host(host, index) for index, host in enumerate(allowed_hosts_value))
    if len(hosts) != len(set(hosts)):
        raise PolicyValidationError("allowed_hosts must not contain duplicates")

    rules_value = document.get("rules")
    if not isinstance(rules_value, list) or not rules_value:
        raise PolicyValidationError("rules must be a non-empty list")
    rules = tuple(_parse_rule(item, index) for index, item in enumerate(rules_value))
    rule_ids = [rule.id for rule in rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise PolicyValidationError("rule ids must be unique")

    return Policy(
        version=version,
        default_action=default_action,
        allowed_hosts=frozenset(hosts),
        rules=rules,
    )
