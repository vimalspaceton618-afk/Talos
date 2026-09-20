"""Pydantic models used by the AgentGuard security pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceType(StrEnum):
    """Supported sources of untrusted content."""

    EMAIL = "email"
    FILE = "file"
    WEB = "web"


class PolicyAction(StrEnum):
    """Action taken by a security policy after scanning content."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    PENDING = "pending"


class ApprovalStatus(StrEnum):
    """Human or automated approval state for a security event."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class SecurityEvent(BaseModel):
    """Validated representation of content inspected by AgentGuard."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: SourceType
    untrusted_content: str
    sanitized_content: str | None = None
    threat_category: str | None = None
    risk_score: float = Field(ge=0, le=100)
    policy_action: PolicyAction
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        """Reject naive timestamps so audit records remain unambiguous."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")
        return value


class ToolCallPayload(BaseModel):
    """Untrusted tool-call data submitted by an AI agent for inspection."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=255)
    tool_name: str = Field(min_length=1, max_length=255)
    parameters: dict[str, Any] = Field(default_factory=dict)
    target_recipient: str | None = Field(default=None, max_length=2048)
    content: str | None = None


class ScanResult(BaseModel):
    """Structured output from a content or tool-call security scanner."""

    model_config = ConfigDict(extra="forbid")

    is_flagged: bool
    threat_type: str | None = None
    score: float = Field(ge=0, le=100)
    detected_entities: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)


__all__ = [
    "ApprovalStatus",
    "PolicyAction",
    "ScanResult",
    "SecurityEvent",
    "SourceType",
    "ToolCallPayload",
]
