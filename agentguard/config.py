"""Application configuration for AgentGuard.

Values can be overridden with environment variables while retaining safe defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


LOW_RISK_THRESHOLD = 30
HIGH_RISK_THRESHOLD = 80
DATABASE_URL = "sqlite:///./agentguard.db"


def _read_score(name: str, default: int) -> int:
    """Read and validate a risk threshold from an environment variable."""
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer between 0 and 100") from exc
    if not 0 <= value <= 100:
        raise ValueError(f"{name} must be between 0 and 100")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable runtime configuration loaded from environment variables."""

    low_risk_threshold: int = LOW_RISK_THRESHOLD
    high_risk_threshold: int = HIGH_RISK_THRESHOLD
    database_url: str = DATABASE_URL

    def __post_init__(self) -> None:
        """Ensure threshold boundaries are ordered and valid."""
        if not 0 <= self.low_risk_threshold <= 100:
            raise ValueError("low_risk_threshold must be between 0 and 100")
        if not 0 <= self.high_risk_threshold <= 100:
            raise ValueError("high_risk_threshold must be between 0 and 100")
        if self.low_risk_threshold >= self.high_risk_threshold:
            raise ValueError("low_risk_threshold must be less than high_risk_threshold")
        if not self.database_url:
            raise ValueError("database_url must not be empty")

    @classmethod
    def from_environment(cls) -> "Settings":
        """Build settings from ``AGENTGUARD_*`` environment variables."""
        return cls(
            low_risk_threshold=_read_score("AGENTGUARD_LOW_RISK_THRESHOLD", LOW_RISK_THRESHOLD),
            high_risk_threshold=_read_score("AGENTGUARD_HIGH_RISK_THRESHOLD", HIGH_RISK_THRESHOLD),
            database_url=os.getenv("AGENTGUARD_DATABASE_URL", DATABASE_URL),
        )


settings = Settings.from_environment()

__all__ = ["DATABASE_URL", "HIGH_RISK_THRESHOLD", "LOW_RISK_THRESHOLD", "Settings", "settings"]
