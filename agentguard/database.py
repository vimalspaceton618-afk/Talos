"""SQLite persistence layer for AgentGuard audit and policy data."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings
from .models import ApprovalStatus, PolicyAction, SecurityEvent, SourceType


def _as_utc(value: datetime) -> datetime:
    """Attach UTC to SQLite timestamps, which may lose timezone metadata."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    """Base class for AgentGuard database models."""


class AuditLog(Base):
    """SQLAlchemy representation of an immutable security audit event."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    untrusted_content: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    policy_action: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)


class QuarantineItem(Base):
    """Content held for review before release or rejection."""

    __tablename__ = "quarantine_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("audit_logs.id"), nullable=False, unique=True, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=ApprovalStatus.PENDING.value, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SecurityPolicy(Base):
    """Configurable policy definition used by the scanning pipeline."""

    __tablename__ = "security_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rules: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def create_engine_for_url(database_url: str = settings.database_url) -> Engine:
    """Create a SQLAlchemy engine configured for SQLite and safe thread use."""
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, future=True)


engine = create_engine_for_url()
SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def init_db(database_engine: Engine = engine) -> None:
    """Create all AgentGuard tables if they do not already exist."""
    Base.metadata.create_all(database_engine)
    if "quarantine_queue" in inspect(database_engine).get_table_names():
        columns = {column["name"] for column in inspect(database_engine).get_columns("quarantine_queue")}
        if "admin_notes" not in columns:
            with database_engine.begin() as connection:
                connection.execute(text("ALTER TABLE quarantine_queue ADD COLUMN admin_notes TEXT"))


def get_session() -> Iterator[Session]:
    """Yield a database session and guarantee its closure."""
    session = SessionFactory()
    try:
        yield session
    finally:
        session.close()


def log_security_event(event: SecurityEvent, session: Session | None = None) -> SecurityEvent:
    """Persist a security event to ``audit_logs`` and return the validated event."""
    owns_session = session is None
    active_session = session or SessionFactory()
    record = AuditLog(
        id=str(event.id),
        timestamp=event.timestamp,
        source_type=event.source_type.value,
        untrusted_content=event.untrusted_content,
        sanitized_content=event.sanitized_content,
        threat_category=event.threat_category,
        risk_score=event.risk_score,
        policy_action=event.policy_action.value,
        approval_status=event.approval_status.value,
    )
    try:
        active_session.add(record)
        active_session.commit()
        return event
    except Exception:
        active_session.rollback()
        raise
    finally:
        if owns_session:
            active_session.close()


def save_quarantine_item(
    event: SecurityEvent,
    session: Session | None = None,
) -> int:
    """Persist a security event and queue its untrusted content for review."""
    owns_session = session is None
    active_session = session or SessionFactory()
    try:
        if active_session.get(AuditLog, str(event.id)) is None:
            active_session.add(
                AuditLog(
                    id=str(event.id),
                    timestamp=event.timestamp,
                    source_type=event.source_type.value,
                    untrusted_content=event.untrusted_content,
                    sanitized_content=event.sanitized_content,
                    threat_category=event.threat_category,
                    risk_score=event.risk_score,
                    policy_action=PolicyAction.QUARANTINE.value,
                    approval_status=ApprovalStatus.PENDING.value,
                )
            )
        item = QuarantineItem(
            event_id=str(event.id),
            content=event.untrusted_content,
            status=ApprovalStatus.PENDING.value,
            created_at=datetime.now(timezone.utc),
        )
        active_session.add(item)
        active_session.commit()
        return item.id
    except Exception:
        active_session.rollback()
        raise
    finally:
        if owns_session:
            active_session.close()


def update_approval_status(
    event_id: UUID,
    status: ApprovalStatus,
    reviewer: str | None = None,
    session: Session | None = None,
) -> bool:
    """Update approval status in audit and quarantine records.

    Returns ``True`` when an audit event was found and updated, otherwise ``False``.
    """
    owns_session = session is None
    active_session = session or SessionFactory()
    event_key = str(event_id)
    try:
        audit_log = active_session.get(AuditLog, event_key)
        if audit_log is None:
            return False
        audit_log.approval_status = status.value
        quarantine_item = active_session.scalar(
            select(QuarantineItem).where(QuarantineItem.event_id == event_key)
        )
        if quarantine_item is not None:
            quarantine_item.status = status.value
            quarantine_item.reviewer = reviewer
            quarantine_item.reviewed_at = (
                None if status is ApprovalStatus.PENDING else datetime.now(timezone.utc)
            )
        active_session.commit()
        return True
    except Exception:
        active_session.rollback()
        raise
    finally:
        if owns_session:
            active_session.close()


def fetch_logs(
    limit: int = 100,
    offset: int = 0,
    session: Session | None = None,
) -> list[SecurityEvent]:
    """Return audit events ordered from newest to oldest."""
    if limit < 1 or offset < 0:
        raise ValueError("limit must be positive and offset must be non-negative")
    owns_session = session is None
    active_session = session or SessionFactory()
    try:
        records = active_session.scalars(
            select(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
        ).all()
        return [
            SecurityEvent(
                id=UUID(record.id),
                timestamp=_as_utc(record.timestamp),
                source_type=SourceType(record.source_type),
                untrusted_content=record.untrusted_content,
                sanitized_content=record.sanitized_content,
                threat_category=record.threat_category,
                risk_score=record.risk_score,
                policy_action=PolicyAction(record.policy_action),
                approval_status=ApprovalStatus(record.approval_status),
            )
            for record in records
        ]
    finally:
        if owns_session:
            active_session.close()


__all__ = [
    "AuditLog",
    "Base",
    "QuarantineItem",
    "SecurityPolicy",
    "SessionFactory",
    "create_engine_for_url",
    "engine",
    "fetch_logs",
    "get_session",
    "init_db",
    "log_security_event",
    "save_quarantine_item",
    "update_approval_status",
]
