"""Wire types — CloudEvent envelope and Verdict shape."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityHint = Literal["low", "medium", "high", "critical"]
VerdictHint = Literal["allow", "approve", "deny"]


def _camel(snake: str) -> str:
    head, *tail = snake.split("_")
    return head + "".join(part.title() for part in tail)


class _CamelModel(BaseModel):
    """Snake-case in Python, camelCase on the wire."""

    model_config = ConfigDict(
        alias_generator=_camel,
        populate_by_name=True,
    )


class Evidence(_CamelModel):
    label: str
    value_redacted: str = Field(alias="valueRedacted")


class UserFacing(_CamelModel):
    headline: str
    body: str
    evidence: list[Evidence] | None = None
    remediation: str | None = None


class ActionAxes(_CamelModel):
    """Per-action risk axes — all integers in [0, 20]."""

    destructive: int = Field(0, ge=0, le=20)
    exfil: int = Field(0, ge=0, le=20)
    secret: int = Field(0, ge=0, le=20)
    privesc: int = Field(0, ge=0, le=20)
    reversibility: int = Field(0, ge=0, le=20)


class ActionScore(_CamelModel):
    """One scored agent action. `action_ref` is the platform-emitted
    ``"{kind}:{index}"`` join key (kind ∈ domain|file|command)."""

    action_ref: str = Field(..., max_length=64)
    risk_score: int = Field(..., ge=0, le=100)
    severity: SeverityHint
    threat_category: str
    axes: ActionAxes


class Verdict(_CamelModel):
    risk_score: int | None = None
    severity_hint: SeverityHint | None = None
    verdict_hint: VerdictHint | None = None
    rule_id: str | None = None
    rationale_summary: str | None = None
    user_facing: UserFacing | None = None
    enrichment: dict[str, Any] | None = None
    latency_ms: int | None = None
    actions: list[ActionScore] | None = None


class _Agent(BaseModel):
    platform: str | None = None
    version: str | None = None


class _ToolCall(BaseModel):
    name: str | None = None
    input: dict[str, Any] | None = None


class _Request(BaseModel):
    categories_requested: list[str] | None = None
    latency_budget_ms: int | None = None
    execution_mode: Literal["sync", "async"] | None = None


class PriorConfigState(_CamelModel):
    """Prior config-artifact state for stateful configuration_threat /
    tool-integrity detectors. Carried as the CloudEvents extension attribute
    ``priorconfigstate`` and surfaced here as ``CloudEvent.prior_config_state``.
    Populated by the platform only when the capability declares
    ``needs_prior_config_state: true``."""

    prior_artifact_payload: dict[str, Any] | None = None
    sibling_skill_names: list[str] = Field(default_factory=list)
    prior_hooks_block: dict[str, Any] | None = None


class CloudEvent(BaseModel):
    """Inbound event envelope — CloudEvents-shaped per `event-envelope.schema.json`."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: int | None = None
    event_id: str | None = None
    org_id: str | None = None
    agent: _Agent | None = None
    event_type: str | None = None
    tool_call: _ToolCall | None = None
    request: _Request | None = None
    redaction_applied: dict[str, Any] | None = None
    prior_config_state: PriorConfigState | None = Field(default=None, alias="priorconfigstate")
    data: Any | None = None


MAX_VERDICT_BYTES = 250 * 1024
