"""Human-in-the-loop quarantine queue engine for AgentGuard.

The manager provides durable review-state transitions in SQLite, an in-process
resume callback registry for approved actions, and a thread-safe notifier that
can be bridged to a WebSocket, SSE stream, or UI event bus by an application.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable, Iterator
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import database
from .database import AuditLog, QuarantineItem
from .models import ApprovalStatus, PolicyAction, SecurityEvent, SourceType


ResumeCallback = Callable[[], Any]
NotificationSubscriber = Callable[["QuarantineNotification"], None]


@dataclass(frozen=True, slots=True)
class QuarantineNotification:
    """Event delivered to subscribers when enforcement needs operator attention."""

    event_type: str
    event_id: UUID
    quarantine_id: int | None
    risk_score: int
    threat_category: str | None
    message: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalResult:
    """Result of an approve or reject operation."""

    quarantine_id: int
    event_id: UUID
    status: ApprovalStatus
    admin_notes: str
    reviewed_at: datetime
    resumed: bool = False
    resume_result: Any | None = None


_callbacks: dict[int, ResumeCallback] = {}
_subscribers: set[NotificationSubscriber] = set()
_registry_lock = RLock()


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """Normalize a SQLite timestamp for typed results and notifications."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _resolve_item(session: Session, quarantine_id: str) -> tuple[QuarantineItem, AuditLog]:
    """Resolve a queue row by integer queue ID or security-event UUID."""
    try:
        item = session.get(QuarantineItem, int(quarantine_id))
    except (TypeError, ValueError):
        item = session.scalar(select(QuarantineItem).where(QuarantineItem.event_id == str(quarantine_id)))
    event = session.get(AuditLog, item.event_id) if item else None
    if item is None or event is None:
        raise KeyError(f"Quarantine item not found: {quarantine_id}")
    return item, event


def subscribe_notifications(subscriber: NotificationSubscriber) -> Callable[[], None]:
    """Subscribe to approval-required or blocked events.

    Returns an unsubscribe function. Subscriber exceptions are isolated from the
    caller that emitted the notification so one broken UI connection cannot
    prevent other subscribers from receiving events.
    """
    with _registry_lock:
        _subscribers.add(subscriber)

    def unsubscribe() -> None:
        with _registry_lock:
            _subscribers.discard(subscriber)

    return unsubscribe


def _emit(notification: QuarantineNotification) -> None:
    """Deliver a notification to a snapshot of current subscribers."""
    with _registry_lock:
        subscribers = tuple(_subscribers)
    for subscriber in subscribers:
        try:
            subscriber(notification)
        except Exception:
            continue


def notify_security_event(
    event_id: UUID,
    decision: str,
    risk_score: int,
    threat_category: str | None = None,
) -> None:
    """Notify UI subscribers for a REQUIRE_APPROVAL or BLOCK enforcement event."""
    normalized = decision.casefold()
    if normalized not in {"require_approval", "block", "quarantine"}:
        return
    event_type = "approval_required" if normalized in {"require_approval", "quarantine"} else "blocked"
    _emit(
        QuarantineNotification(
            event_type=event_type,
            event_id=event_id,
            quarantine_id=None,
            risk_score=risk_score,
            threat_category=threat_category,
            message=(
                "Action is waiting for human approval."
                if event_type == "approval_required"
                else "Action was blocked by the AgentGuard policy engine."
            ),
            created_at=_utc_now(),
        )
    )


def add_suspicious_action(
    event: SecurityEvent,
    resume_callback: ResumeCallback | None = None,
) -> int:
    """Add an action to the durable queue with ``PENDING`` status.

    ``resume_callback`` is registered only after the database commit succeeds.
    It should contain the middleware's safe re-trigger operation and must be
    idempotent because operators may retry a transient callback failure.
    """
    queued_event = event.model_copy(
        update={"policy_action": PolicyAction.QUARANTINE, "approval_status": ApprovalStatus.PENDING}
    )
    queue_id = database.save_quarantine_item(queued_event)
    if resume_callback is not None:
        with _registry_lock:
            _callbacks[queue_id] = resume_callback
    _emit(
        QuarantineNotification(
            event_type="approval_required",
            event_id=queued_event.id,
            quarantine_id=queue_id,
            risk_score=int(round(queued_event.risk_score)),
            threat_category=queued_event.threat_category,
            message="Suspicious action added to the HITL quarantine queue.",
            created_at=_utc_now(),
        )
    )
    return queue_id


def register_resume_callback(quarantine_id: str, callback: ResumeCallback) -> None:
    """Register or replace the callback used when an item is approved."""
    if not callable(callback):
        raise TypeError("callback must be callable")
    with _registry_lock:
        try:
            queue_key = int(quarantine_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("resume callback registration requires an integer quarantine ID") from exc
        _callbacks[queue_key] = callback


def _review(
    quarantine_id: str,
    admin_notes: str,
    status: ApprovalStatus,
) -> ApprovalResult:
    """Atomically transition one pending queue row and optionally resume it."""
    if not isinstance(admin_notes, str):
        raise TypeError("admin_notes must be a string")
    if len(admin_notes) > 10_000:
        raise ValueError("admin_notes must be 10,000 characters or fewer")

    with _registry_lock:
        session = database.SessionFactory()
        try:
            item, event = _resolve_item(session, quarantine_id)
            if item.status != ApprovalStatus.PENDING.value:
                raise RuntimeError(f"Quarantine item is already resolved as {item.status}")
            reviewed_at = _utc_now()
            item.status = status.value
            item.reviewer = "admin"
            item.admin_notes = admin_notes.strip()
            item.reviewed_at = reviewed_at
            event.approval_status = status.value
            session.commit()
            callback = _callbacks.get(item.id) if status is ApprovalStatus.APPROVED else None
            result = ApprovalResult(
                quarantine_id=item.id,
                event_id=UUID(item.event_id),
                status=status,
                admin_notes=item.admin_notes,
                reviewed_at=reviewed_at,
            )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    if callback is not None:
        try:
            resume_result = callback()
            with _registry_lock:
                _callbacks.pop(result.quarantine_id, None)
            result = ApprovalResult(
                quarantine_id=result.quarantine_id,
                event_id=result.event_id,
                status=result.status,
                admin_notes=result.admin_notes,
                reviewed_at=result.reviewed_at,
                resumed=True,
                resume_result=resume_result,
            )
        except Exception:
            # The approval is durable; retain it and surface callback failure to
            # the caller so an operator can retry through a separate workflow.
            raise
    return result


def approve_quarantined_action(quarantine_id: str, admin_notes: str) -> ApprovalResult:
    """Approve a pending action, persist notes, and invoke its resume callback."""
    return _review(quarantine_id, admin_notes, ApprovalStatus.APPROVED)


def reject_quarantined_action(quarantine_id: str, admin_notes: str) -> ApprovalResult:
    """Reject a pending action, persist notes, and discard its resume callback."""
    return _review(quarantine_id, admin_notes, ApprovalStatus.REJECTED)


if __name__ == "__main__":
    import unittest
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    class QuarantineManagerTests(unittest.TestCase):
        """Standalone queue, callback, and notifier examples."""

        @classmethod
        def setUpClass(cls) -> None:
            cls.original_factory = database.SessionFactory
            cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
            database.SessionFactory = database.sessionmaker(bind=cls.engine, autoflush=False, expire_on_commit=False)
            database.init_db(cls.engine)

        @classmethod
        def tearDownClass(cls) -> None:
            database.SessionFactory = cls.original_factory

        def _event(self, risk: float = 72) -> SecurityEvent:
            return SecurityEvent(
                source_type=SourceType.WEB,
                untrusted_content="Suspicious tool action awaiting review.",
                threat_category="unauthorized_destination",
                risk_score=risk,
                policy_action=PolicyAction.QUARANTINE,
                approval_status=ApprovalStatus.PENDING,
            )

        def test_approval_persists_notes_and_resumes(self) -> None:
            resumed: list[bool] = []
            queue_id = add_suspicious_action(self._event(), lambda: resumed.append(True) or {"status": "executed"})
            result = approve_quarantined_action(str(queue_id), "Approved after verifying the recipient.")
            self.assertEqual(result.status, ApprovalStatus.APPROVED)
            self.assertTrue(result.resumed)
            self.assertTrue(resumed)
            self.assertEqual(result.admin_notes, "Approved after verifying the recipient.")

        def test_rejection_does_not_resume(self) -> None:
            resumed: list[bool] = []
            queue_id = add_suspicious_action(self._event(), lambda: resumed.append(True))
            result = reject_quarantined_action(str(queue_id), "External destination was not verified.")
            self.assertEqual(result.status, ApprovalStatus.REJECTED)
            self.assertFalse(resumed)

        def test_double_review_is_rejected(self) -> None:
            queue_id = add_suspicious_action(self._event())
            approve_quarantined_action(str(queue_id), "Approved")
            with self.assertRaises(RuntimeError):
                reject_quarantined_action(str(queue_id), "Too late")

        def test_notifier_receives_approval_event(self) -> None:
            notifications: list[QuarantineNotification] = []
            unsubscribe = subscribe_notifications(notifications.append)
            try:
                queue_id = add_suspicious_action(self._event())
                self.assertEqual(notifications[-1].event_type, "approval_required")
                self.assertEqual(notifications[-1].quarantine_id, queue_id)
            finally:
                unsubscribe()

        def test_block_notification(self) -> None:
            notifications: list[QuarantineNotification] = []
            unsubscribe = subscribe_notifications(notifications.append)
            try:
                event_id = UUID("00000000-0000-0000-0000-000000000001")
                notify_security_event(event_id, "block", 99, "api_key")
                self.assertEqual(notifications[-1].event_type, "blocked")
                self.assertEqual(notifications[-1].risk_score, 99)
            finally:
                unsubscribe()

    unittest.main()
