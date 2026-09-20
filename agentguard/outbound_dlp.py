"""Outbound Data Loss Prevention engine for AgentGuard.

This module scans agent responses and planned tool-call payloads before execution.
It is local-first and deterministic: detected secrets and PII are redacted in a
copy of the payload, while destination policy checks fail closed for sensitive
transmissions to non-whitelisted recipients.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from enum import StrEnum
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qs, urlparse

from .models import ScanResult


class FindingType(StrEnum):
    """Data classes recognized by the DLP engine."""

    OPENAI_API_KEY = "api_key"
    AWS_ACCESS_KEY = "aws_access_key"
    GITHUB_TOKEN = "github_token"
    JWT = "jwt"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PASSWORD = "password"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    STREET_ADDRESS = "street_address"
    EXFILTRATION_URL = "exfiltration_url"
    UNAUTHORIZED_DESTINATION = "unauthorized_destination"


@dataclass(frozen=True, slots=True)
class DLPPolicy:
    """Configurable destination policy for sensitive outbound payloads."""

    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    allowed_email_addresses: frozenset[str] = field(default_factory=frozenset)
    allowed_email_domains: frozenset[str] = field(default_factory=frozenset)
    sensitive_file_extensions: frozenset[str] = frozenset({".pem", ".key", ".env", ".csv", ".sql", ".json"})

    def __post_init__(self) -> None:
        """Normalize domain and email values for case-insensitive matching."""
        object.__setattr__(self, "allowed_domains", frozenset(_normalize_domain(value) for value in self.allowed_domains))
        object.__setattr__(self, "allowed_email_addresses", frozenset(value.casefold().strip() for value in self.allowed_email_addresses))
        object.__setattr__(self, "allowed_email_domains", frozenset(_normalize_domain(value) for value in self.allowed_email_domains))
        object.__setattr__(self, "sensitive_file_extensions", frozenset(value.casefold() if value.startswith(".") else f".{value.casefold()}" for value in self.sensitive_file_extensions))


DEFAULT_DLP_POLICY = DLPPolicy()


# The prefixes and lengths below intentionally follow provider-issued token formats.
_SECRET_PATTERNS: tuple[tuple[FindingType, re.Pattern[str]], ...] = (
    (FindingType.OPENAI_API_KEY, re.compile(r"(?<![A-Za-z0-9])sk-(?:proj|org)?-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])")),
    (FindingType.AWS_ACCESS_KEY, re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])")),
    (FindingType.GITHUB_TOKEN, re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    (FindingType.JWT, re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")),
    (FindingType.SSH_PRIVATE_KEY, re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    (FindingType.PASSWORD, re.compile(r"(?i)(?<![A-Za-z0-9_])(?:password|passwd|pwd|passphrase)\s*[:=]\s*(['\"]?)(?=[^\s,;}]*)[^\s,;}'\"]+\1")),
)

_PII_PATTERNS: tuple[tuple[FindingType, re.Pattern[str]], ...] = (
    (FindingType.SSN, re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?!\d)")),
    (FindingType.EMAIL, re.compile(r"(?i)(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![A-Za-z0-9._%+-])")),
    (FindingType.PHONE, re.compile(r"(?<!\d)(?:\+?1[ .-]?)?(?:\(?[2-9]\d{2}\)?[ .-]?)\d{3}[ .-]\d{4}(?!\d)")),
    (FindingType.STREET_ADDRESS, re.compile(r"(?i)(?<![\w])\d{1,6}\s+[A-Za-z][A-Za-z0-9.'-]*(?:\s+[A-Za-z][A-Za-z0-9.'-]*){0,5}\s+(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|lane|ln\.?|drive|dr\.?|court|ct\.?|way|parkway|pkwy\.?)\b")),
)

_DESTINATION_KEYS = frozenset({"to", "recipient", "recipients", "email", "email_to", "target_recipient", "url", "endpoint", "webhook", "destination", "filename", "path"})
_TRANSMISSION_TOOLS = frozenset({"send_email", "send_mail", "send_message", "upload_file", "http_post", "post", "webhook", "share_file", "export_data"})
_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>'\"]+")
_EXFILTRATION_QUERY_KEYS = frozenset({"data", "token", "secret", "key", "password", "credential", "apikey", "api_key"})


@dataclass(frozen=True, slots=True)
class _Match:
    """One typed sensitive-data match."""

    kind: FindingType
    value: str


@dataclass(frozen=True, slots=True)
class _ScanDetails:
    """Internal scan output used to build the public ScanResult."""

    matches: tuple[_Match, ...]
    unauthorized_destinations: tuple[str, ...]


def _normalize_domain(value: str) -> str:
    """Normalize an email domain, hostname, or URL to a bare lowercase domain."""
    candidate = value.casefold().strip()
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or candidate
    else:
        candidate = candidate.split("/", 1)[0].split(":", 1)[0]
    return candidate.rstrip(".")


def _is_luhn_valid(value: str) -> bool:
    """Validate a payment-card candidate with the Luhn checksum."""
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(map(int, digits)):
        addend = digit * (2 if index % 2 == parity else 1)
        checksum += addend - 9 if addend > 9 else addend
    return checksum % 10 == 0


def _card_matches(text: str) -> Iterable[_Match]:
    """Yield only payment-card candidates that pass Luhn validation."""
    pattern = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
    for match in pattern.finditer(text):
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if _is_luhn_valid(candidate) and not (digits[0] == "0" or len(set(digits)) == 1):
            yield _Match(FindingType.CREDIT_CARD, candidate)


def _scan_text(text: str) -> tuple[_Match, ...]:
    """Scan one string for secrets and PII, preserving match order."""
    matches: list[_Match] = []
    for kind, pattern in _SECRET_PATTERNS + _PII_PATTERNS:
        matches.extend(_Match(kind, match.group(0)) for match in pattern.finditer(text))
    matches.extend(_card_matches(text))
    for url_match in _URL_PATTERN.finditer(text):
        query = urlparse(url_match.group(0).rstrip(".,;:!?)]}")).query
        if set(parse_qs(query, keep_blank_values=True)) & _EXFILTRATION_QUERY_KEYS:
            matches.append(_Match(FindingType.EXFILTRATION_URL, url_match.group(0)))
    return tuple(sorted(matches, key=lambda match: text.find(match.value)))


def _iter_texts(value: Any) -> Iterable[str]:
    """Yield string leaves from arbitrary JSON-compatible payload data."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_texts(child)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            yield from _iter_texts(child)


def _replace_matches(text: str) -> tuple[str, list[FindingType]]:
    """Replace sensitive substrings with stable typed redaction tokens."""
    replacements: list[tuple[int, int, str, FindingType]] = []
    for kind, pattern in _SECRET_PATTERNS + _PII_PATTERNS:
        for match in pattern.finditer(text):
            replacements.append((match.start(), match.end(), f"[REDACTED_{kind.value.upper()}]", kind))
    for match in _card_matches(text):
        start = text.find(match.value)
        if start >= 0:
            replacements.append((start, start + len(match.value), f"[REDACTED_{match.kind.value.upper()}]", match.kind))
    replacements.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    output: list[str] = []
    found: list[FindingType] = []
    cursor = 0
    for start, end, token, kind in replacements:
        if start < cursor:
            continue
        output.append(text[cursor:start])
        output.append(token)
        cursor = end
        found.append(kind)
    output.append(text[cursor:])
    return "".join(output), found


def redact_sensitive_data(payload: dict) -> tuple[dict, list[str]]:
    """Return a recursively redacted copy and unique detected data-type labels.

    The input object is never mutated. Dictionary keys are preserved, while
    sensitive values embedded in strings, lists, and nested mappings are masked.
    """
    detected: list[str] = []

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            redacted, kinds = _replace_matches(value)
            for kind in kinds:
                if kind.value not in detected:
                    detected.append(kind.value)
            return redacted
        if isinstance(value, dict):
            return {key: redact(child) for key, child in value.items()}
        if isinstance(value, list):
            return [redact(child) for child in value]
        if isinstance(value, tuple):
            return tuple(redact(child) for child in value)
        return value

    return redact(payload), detected


def _extract_destinations(payload: dict, policy: DLPPolicy) -> tuple[list[str], list[str]]:
    """Extract recipient-like values and file paths from a nested payload."""
    destinations: list[str] = []
    sensitive_files: list[str] = []

    def walk(value: Any, key: str | None = None) -> None:
        if isinstance(value, Mapping):
            for child_key, child in value.items():
                walk(child, str(child_key).casefold())
        elif isinstance(value, (list, tuple, set, frozenset)):
            for child in value:
                walk(child, key)
        elif isinstance(value, str):
            if key in _DESTINATION_KEYS:
                destinations.append(value)
            if key in {"filename", "file_name", "path", "attachment", "attachments"} and any(value.casefold().endswith(ext) for ext in policy.sensitive_file_extensions):
                sensitive_files.append(value)

    walk(payload)
    return destinations, sensitive_files


def _destination_allowed(destination: str, policy: DLPPolicy) -> bool:
    """Check an email address, URL, or hostname against the configured whitelist."""
    candidate = destination.strip().strip("<>[](){}\"'").casefold()
    parsed = urlparse(candidate if "://" in candidate else "")
    if parsed.hostname:
        domain = _normalize_domain(parsed.hostname)
        return domain in policy.allowed_domains or any(domain.endswith(f".{allowed}") for allowed in policy.allowed_domains if allowed)
    address = parseaddr(candidate)[1].casefold()
    if "@" in address:
        domain = _normalize_domain(address)
        return address in policy.allowed_email_addresses or domain in policy.allowed_email_domains or domain in policy.allowed_domains or any(domain.endswith(f".{allowed}") for allowed in policy.allowed_domains if allowed)
    return _normalize_domain(candidate) in policy.allowed_domains


def _scan_payload(tool_name: str, payload: dict, policy: DLPPolicy) -> _ScanDetails:
    """Collect sensitive matches and unauthorized destinations."""
    matches: list[_Match] = []
    for text in _iter_texts(payload):
        matches.extend(_scan_text(text))
    destinations, sensitive_files = _extract_destinations(payload, policy)
    unauthorized: list[str] = []
    sensitive_present = bool(matches) or bool(sensitive_files)
    if sensitive_present and (tool_name.casefold() in _TRANSMISSION_TOOLS or destinations):
        for destination in destinations:
            if ("@" in destination or "://" in destination or "." in destination) and not _destination_allowed(destination, policy):
                unauthorized.append(destination)
    return _ScanDetails(tuple(matches), tuple(dict.fromkeys(unauthorized)))


def scan_outbound_payload(tool_name: str, payload: dict, policy: DLPPolicy = DEFAULT_DLP_POLICY) -> ScanResult:
    """Scan a planned tool call and summarize exposed data and policy violations.

    Sensitive values are redacted by the same engine used by
    :func:`redact_sensitive_data`; callers that need the sanitized payload should
    call that function with the original dictionary. The returned ``ScanResult``
    contains only categories, scores, and safe explanations—not raw secrets.
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")

    details = _scan_payload(tool_name, payload, policy)
    categories = list(dict.fromkeys(match.kind.value for match in details.matches))
    entities = list(categories)
    explanations: list[str] = []
    if categories:
        explanations.append(f"Detected sensitive outbound data types: {', '.join(categories)}.")
        explanations.append("Sensitive values should be redacted before tool execution.")
    if details.unauthorized_destinations:
        categories.append(FindingType.UNAUTHORIZED_DESTINATION.value)
        entities.append(FindingType.UNAUTHORIZED_DESTINATION.value)
        explanations.append("Sensitive payload targets a destination outside the configured whitelist.")
    score = min(100.0, len(set(match.kind for match in details.matches)) * 18.0 + len(details.unauthorized_destinations) * 40.0)
    return ScanResult(
        is_flagged=bool(categories),
        threat_type=", ".join(dict.fromkeys(categories)) if categories else None,
        score=round(score, 2),
        detected_entities=list(dict.fromkeys(entities)),
        explanations=explanations,
    )


if __name__ == "__main__":
    import unittest

    class OutboundDLPTests(unittest.TestCase):
        """Standalone examples for secret, PII, redaction, and destination checks."""

        def test_secret_and_pii_detection(self) -> None:
            payload = {"body": "Contact jane@example.com, SSN 123-45-6789, key sk-proj-abcdefghijklmnopqrstuvwxyz123456."}
            result = scan_outbound_payload("send_email", payload)
            self.assertTrue(result.is_flagged)
            self.assertIn("api_key", result.detected_entities)
            self.assertIn("ssn", result.detected_entities)
            self.assertIn("email", result.detected_entities)

        def test_luhn_filters_card_candidates(self) -> None:
            valid = scan_outbound_payload("send_email", {"body": "Card 4111 1111 1111 1111"})
            invalid = scan_outbound_payload("send_email", {"body": "Card 4111 1111 1111 1112"})
            self.assertIn("credit_card", valid.detected_entities)
            self.assertNotIn("credit_card", invalid.detected_entities)

        def test_recursive_redaction_does_not_mutate_input(self) -> None:
            payload = {"nested": ["token ghp_" + "a" * 36, {"email": "jane@example.com"}]}
            redacted, labels = redact_sensitive_data(payload)
            self.assertEqual(payload["nested"][1]["email"], "jane@example.com")
            self.assertIn("github_token", labels)
            self.assertIn("[REDACTED_GITHUB_TOKEN]", redacted["nested"][0])
            self.assertEqual(redacted["nested"][1]["email"], "[REDACTED_EMAIL]")

        def test_unauthorized_destination(self) -> None:
            policy = DLPPolicy(allowed_domains=frozenset({"example.com"}))
            result = scan_outbound_payload("send_email", {"to": "attacker.example", "body": "password=secret-value"}, policy)
            self.assertIn("unauthorized_destination", result.detected_entities)

        def test_whitelisted_destination(self) -> None:
            policy = DLPPolicy(allowed_domains=frozenset({"example.com"}))
            result = scan_outbound_payload("send_email", {"to": "ops@example.com", "body": "password=secret-value"}, policy)
            self.assertNotIn("unauthorized_destination", result.detected_entities)
            self.assertIn("password", result.detected_entities)

        def test_benign_text(self) -> None:
            result = scan_outbound_payload("calendar_lookup", {"query": "team planning on Tuesday"})
            self.assertFalse(result.is_flagged)
            self.assertEqual(result.score, 0.0)

    unittest.main()
