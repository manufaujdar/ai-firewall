from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class Finding(BaseModel):
    rule_id: str
    severity: str
    action: Action
    path: str
    count: int = 1


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: Any


class ScanResponse(BaseModel):
    decision: Action
    payload: Any | None = None
    findings: list[Finding] = Field(default_factory=list)


class RuleSummary(BaseModel):
    """Safe operator metadata; the executable regex is never exposed."""

    id: str
    description: str
    action: Action
    severity: str


class PolicySummary(BaseModel):
    version: int
    default_action: Action
    allowed_hosts: list[str]
    rules: list[RuleSummary]


class ProxyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    payload: Any
