"""Risk scoring and enforcement policy engine for AgentGuard."""

from __future__ import annotations

from enum import StrEnum
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from .models import ScanResult


class EnforcementDecision(StrEnum):
    """Actions the firewall may take for a composite risk score."""

    ALLOW = "allow"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class PolicyDecision(BaseModel):
    """Complete policy evaluation result for an inbound/outbound exchange."""

    model_config = ConfigDict(extra="forbid")

    decision: EnforcementDecision
    composite_score: int = Field(ge=0, le=100)
    explanation: str
    threat_categories: list[str] = Field(default_factory=list)
    should_quarantine: bool = False
    should_alert: bool = False
    execution_paused: bool = False


# Categories are intentionally matched by substring so scanner-specific labels
# such as ``system_override`` and ``exposed_secret`` remain interoperable.
_SYSTEM_OVERRIDE_MARKERS = frozenset({
    "system_override",
    "system_prompt_reference",
    "role_override",
    "constraint_reset",
    "prompt_injection",
    "indirect_prompt_injection",
})
_SECRET_MARKERS = frozenset({
    "api_key",
    "aws_access_key",
    "github_token",
    "jwt",
    "ssh_private_key",
    "password",
    "secret",
    "credential",
})
_UNAUTHORIZED_DESTINATION_MARKERS = frozenset({
    "unauthorized_destination",
    "data_exfiltration_url",
    "private-network-url",
    "unauthorized-recipient",
})


def _contains_marker(categories: Iterable[str], markers: frozenset[str]) -> bool:
    """Return whether any normalized category contains a high-severity marker."""
    normalized = [category.casefold().replace("-", "_") for category in categories]
    return any(marker in category for category in normalized for marker in markers)


def _normalized_categories(*scans: ScanResult) -> list[str]:
    """Return unique threat categories from both scan results."""
    categories: list[str] = []
    for scan in scans:
        for value in [scan.threat_type, *scan.detected_entities]:
            if not value:
                continue
            for category in value.split(","):
                normalized = category.strip()
                if normalized and normalized not in categories:
                    categories.append(normalized)
    return categories


def calculate_composite_risk(inbound_scan: ScanResult, outbound_scan: ScanResult) -> int:
    """Calculate a bounded unified risk score from inbound and outbound scans.

    Outbound DLP is weighted slightly more heavily because exposed secrets or an
    unauthorized destination represent an imminent loss-of-control event. Severe
    category markers add explicit escalation points so a high-impact signal is
    not diluted by a benign score from the other direction.
    """
    if not isinstance(inbound_scan, ScanResult) or not isinstance(outbound_scan, ScanResult):
        raise TypeError("inbound_scan and outbound_scan must be ScanResult instances")

    categories = _normalized_categories(inbound_scan, outbound_scan)
    score = (inbound_scan.score * 0.35) + (outbound_scan.score * 0.65)
    if _contains_marker(categories, _SYSTEM_OVERRIDE_MARKERS):
        score += 15
    if _contains_marker(categories, _SECRET_MARKERS):
        score += 24
    if _contains_marker(categories, _UNAUTHORIZED_DESTINATION_MARKERS):
        score += 28
    return max(0, min(100, int(round(score))))


def _category_label(category: str) -> str:
    """Convert a machine category into readable security language."""
    labels = {
        "system_override": "an attempt to override the agent's governing instructions",
        "indirect_prompt_injection": "indirect prompt-injection language",
        "api_key": "an exposed API key",
        "aws_access_key": "an exposed AWS access key",
        "github_token": "an exposed GitHub token",
        "jwt": "an exposed authentication token",
        "ssh_private_key": "an exposed SSH private key",
        "password": "an exposed password",
        "unauthorized_destination": "an unauthorized external destination",
        "data_exfiltration_url": "a possible data-exfiltration URL",
        "email": "an exposed email address",
        "ssn": "an exposed Social Security number",
        "credit_card": "an exposed credit-card number",
    }
    normalized = category.strip().casefold().replace("-", "_")
    return labels.get(normalized, normalized.replace("_", " "))


def generate_explanation(
    decision: EnforcementDecision,
    composite_score: int,
    inbound_scan: ScanResult,
    outbound_scan: ScanResult,
) -> str:
    """Generate a concise, human-readable narrative for an enforcement action."""
    categories = _normalized_categories(inbound_scan, outbound_scan)
    if not categories:
        if decision is EnforcementDecision.ALLOW:
            return f"No material threats were detected; the action is allowed with a composite risk score of {composite_score}/100."
        return f"The action reached a composite risk score of {composite_score}/100 and requires the selected enforcement step."

    readable = [_category_label(category) for category in categories[:4]]
    if len(readable) > 1:
        signal_text = ", ".join(readable[:-1]) + f", and {readable[-1]}"
    else:
        signal_text = readable[0]
    action_text = {
        EnforcementDecision.ALLOW: "The action may proceed.",
        EnforcementDecision.REDACT: "Sensitive values should be substituted with redaction tokens before execution.",
        EnforcementDecision.REQUIRE_APPROVAL: "Execution is paused and the payload must be reviewed by an authorized operator.",
        EnforcementDecision.BLOCK: "Execution is terminated and a security alert should be raised.",
    }[decision]
    return f"Detected {signal_text}. Composite risk is {composite_score}/100. {action_text}"


def evaluate_policy(
    composite_score: int,
    inbound_scan: ScanResult,
    outbound_scan: ScanResult,
) -> PolicyDecision:
    """Map a composite score to the AgentGuard enforcement decision matrix.

    The boundaries are inclusive exactly as specified: ``<30`` allows,
    ``30-59`` redacts, ``60-84`` requires approval, and ``>=85`` blocks.
    """
    if not isinstance(composite_score, int) or isinstance(composite_score, bool):
        raise TypeError("composite_score must be an integer")
    if not 0 <= composite_score <= 100:
        raise ValueError("composite_score must be between 0 and 100")
    if not isinstance(inbound_scan, ScanResult) or not isinstance(outbound_scan, ScanResult):
        raise TypeError("inbound_scan and outbound_scan must be ScanResult instances")

    if composite_score < 30:
        decision = EnforcementDecision.ALLOW
    elif composite_score < 60:
        decision = EnforcementDecision.REDACT
    elif composite_score < 85:
        decision = EnforcementDecision.REQUIRE_APPROVAL
    else:
        decision = EnforcementDecision.BLOCK

    categories = _normalized_categories(inbound_scan, outbound_scan)
    return PolicyDecision(
        decision=decision,
        composite_score=composite_score,
        explanation=generate_explanation(decision, composite_score, inbound_scan, outbound_scan),
        threat_categories=categories,
        should_quarantine=decision is EnforcementDecision.REQUIRE_APPROVAL,
        should_alert=decision is EnforcementDecision.BLOCK,
        execution_paused=decision in {EnforcementDecision.REQUIRE_APPROVAL, EnforcementDecision.BLOCK},
    )


if __name__ == "__main__":
    import unittest

    class PolicyEngineTests(unittest.TestCase):
        """Standalone examples for risk calculation and policy boundaries."""

        def _scan(self, score: float = 0, *categories: str) -> ScanResult:
            return ScanResult(
                is_flagged=score > 0,
                threat_type=", ".join(categories) if categories else None,
                score=score,
                detected_entities=list(categories),
                explanations=[],
            )

        def test_score_is_bounded_and_weights_secrets(self) -> None:
            inbound = self._scan(10, "system_override")
            outbound = self._scan(70, "api_key", "unauthorized_destination")
            score = calculate_composite_risk(inbound, outbound)
            self.assertGreaterEqual(score, 85)
            self.assertLessEqual(score, 100)

        def test_decision_boundaries(self) -> None:
            inbound = self._scan()
            outbound = self._scan()
            self.assertEqual(evaluate_policy(29, inbound, outbound).decision, EnforcementDecision.ALLOW)
            self.assertEqual(evaluate_policy(30, inbound, outbound).decision, EnforcementDecision.REDACT)
            self.assertEqual(evaluate_policy(59, inbound, outbound).decision, EnforcementDecision.REDACT)
            self.assertEqual(evaluate_policy(60, inbound, outbound).decision, EnforcementDecision.REQUIRE_APPROVAL)
            self.assertEqual(evaluate_policy(84, inbound, outbound).decision, EnforcementDecision.REQUIRE_APPROVAL)
            self.assertEqual(evaluate_policy(85, inbound, outbound).decision, EnforcementDecision.BLOCK)

        def test_approval_and_block_flags(self) -> None:
            inbound = self._scan(50, "hidden_html")
            outbound = self._scan(45, "email")
            approval = evaluate_policy(65, inbound, outbound)
            self.assertTrue(approval.should_quarantine)
            self.assertTrue(approval.execution_paused)
            blocked = evaluate_policy(90, inbound, outbound)
            self.assertTrue(blocked.should_alert)
            self.assertTrue(blocked.execution_paused)

        def test_explanation_is_human_readable(self) -> None:
            inbound = self._scan(40, "system_override")
            outbound = self._scan(55, "api_key")
            result = evaluate_policy(86, inbound, outbound)
            self.assertIn("override", result.explanation)
            self.assertIn("terminated", result.explanation)

        def test_invalid_scores(self) -> None:
            inbound = self._scan()
            outbound = self._scan()
            with self.assertRaises(ValueError):
                evaluate_policy(101, inbound, outbound)
            with self.assertRaises(TypeError):
                evaluate_policy(30.0, inbound, outbound)  # type: ignore[arg-type]

    unittest.main()
