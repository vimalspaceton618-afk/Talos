"""FastAPI Human-in-the-Loop approval and quarantine management API."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Iterator
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import database
from .database import AuditLog, QuarantineItem
from .models import ApprovalStatus, PolicyAction, SecurityEvent


class QuarantineCreateRequest(BaseModel):
    """Request body for adding an event to the review queue."""

    model_config = ConfigDict(extra="forbid")

    event: SecurityEvent


class ReviewRequest(BaseModel):
    """Reviewer identity supplied when resolving a quarantine item."""

    model_config = ConfigDict(extra="forbid")

    reviewer: str = Field(min_length=1, max_length=255)


class QuarantineResponse(BaseModel):
    """Public representation of a quarantined event."""

    model_config = ConfigDict(from_attributes=True)

    queue_id: int
    event_id: UUID
    content: str
    status: ApprovalStatus
    created_at: datetime
    reviewed_at: datetime | None = None
    reviewer: str | None = None
    risk_score: float
    threat_category: str | None = None
    source_type: str


class ReviewResponse(BaseModel):
    """Response returned after approving or rejecting an event."""

    event_id: UUID
    status: ApprovalStatus
    reviewer: str
    reviewed_at: datetime


def get_db() -> Iterator[Session]:
    """Provide one request-scoped SQLAlchemy session."""
    yield from database.get_session()


DbSession = Annotated[Session, Depends(get_db)]


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize the persistence schema when the API starts."""
    database.init_db()
    yield


app = FastAPI(
    title="AgentGuard HITL Approval API",
    description="Quarantine review and human approval workflow for AgentGuard.",
    version="1.0.0",
    lifespan=lifespan,
)


def _utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for API responses."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _to_response(item: QuarantineItem, event: AuditLog) -> QuarantineResponse:
    """Convert database rows into a stable API response."""
    return QuarantineResponse(
        queue_id=item.id,
        event_id=UUID(item.event_id),
        content=item.content,
        status=ApprovalStatus(item.status),
        created_at=_utc(item.created_at),
        reviewed_at=_utc(item.reviewed_at) if item.reviewed_at else None,
        reviewer=item.reviewer,
        risk_score=event.risk_score,
        threat_category=event.threat_category,
        source_type=event.source_type,
    )


def _get_queue_item(session: Session, event_id: UUID) -> tuple[QuarantineItem, AuditLog]:
    """Fetch a queue item and its audit event or raise a 404."""
    item = session.scalar(select(QuarantineItem).where(QuarantineItem.event_id == str(event_id)))
    event = session.get(AuditLog, str(event_id))
    if item is None or event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Quarantine item not found")
    return item, event


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Return a lightweight liveness response."""
    return {"status": "ok"}


@app.post(
    "/quarantine",
    response_model=QuarantineResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["quarantine"],
)
def enqueue_quarantine(request: QuarantineCreateRequest, session: DbSession) -> QuarantineResponse:
    """Add an event to the quarantine queue for human review."""
    event = request.event.model_copy(
        update={"policy_action": PolicyAction.QUARANTINE, "approval_status": ApprovalStatus.PENDING}
    )
    try:
        item_id = database.save_quarantine_item(event, session=session)
        item = session.get(QuarantineItem, item_id)
        audit_event = session.get(AuditLog, str(event.id))
        if item is None or audit_event is None:
            raise HTTPException(status_code=500, detail="Failed to create quarantine item")
        return _to_response(item, audit_event)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Event is already queued or cannot be persisted") from exc


@app.get("/quarantine", response_model=list[QuarantineResponse], tags=["quarantine"])
def list_quarantine(
    session: DbSession,
    queue_status: Annotated[ApprovalStatus | None, Query(alias="status")] = ApprovalStatus.PENDING,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[QuarantineResponse]:
    """List queued events, newest first, filtered by review status."""
    query = (
        select(QuarantineItem, AuditLog)
        .join(AuditLog, AuditLog.id == QuarantineItem.event_id)
        .where(QuarantineItem.status == queue_status.value if queue_status else True)
        .order_by(QuarantineItem.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return [_to_response(item, event) for item, event in session.execute(query).all()]


@app.get("/quarantine/{event_id}", response_model=QuarantineResponse, tags=["quarantine"])
def get_quarantine(event_id: UUID, session: DbSession) -> QuarantineResponse:
    """Retrieve one quarantined event by its security-event UUID."""
    item, event = _get_queue_item(session, event_id)
    return _to_response(item, event)


def _review_item(
    event_id: UUID,
    reviewer: str,
    new_status: ApprovalStatus,
    session: Session,
) -> ReviewResponse:
    """Atomically resolve a pending queue item exactly once."""
    item, event = _get_queue_item(session, event_id)
    if item.status != ApprovalStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Quarantine item has already been resolved as {item.status}",
        )
    reviewed_at = datetime.now(timezone.utc)
    item.status = new_status.value
    item.reviewer = reviewer
    item.reviewed_at = reviewed_at
    event.approval_status = new_status.value
    session.commit()
    return ReviewResponse(
        event_id=event_id,
        status=new_status,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
    )


@app.post("/quarantine/{event_id}/approve", response_model=ReviewResponse, tags=["review"])
def approve_quarantine(event_id: UUID, request: ReviewRequest, session: DbSession) -> ReviewResponse:
    """Approve a pending event and record the responsible reviewer."""
    return _review_item(event_id, request.reviewer, ApprovalStatus.APPROVED, session)


@app.post("/quarantine/{event_id}/reject", response_model=ReviewResponse, tags=["review"])
def reject_quarantine(event_id: UUID, request: ReviewRequest, session: DbSession) -> ReviewResponse:
    """Reject a pending event and record the responsible reviewer."""
    return _review_item(event_id, request.reviewer, ApprovalStatus.REJECTED, session)


if __name__ == "__main__":
    import unittest
    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool

    class HitlApiTests(unittest.TestCase):
        """Standalone API examples using an isolated in-memory SQLite database."""

        @classmethod
        def setUpClass(cls) -> None:
            cls.original_engine = database.engine
            cls.original_factory = database.SessionFactory
            cls.test_engine = database.create_engine_for_url("sqlite://",)
            # Recreate with StaticPool so all TestClient requests share one memory DB.
            from sqlalchemy import create_engine
            cls.test_engine = create_engine(
                "sqlite://",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
            database.SessionFactory = database.sessionmaker(bind=cls.test_engine, autoflush=False, expire_on_commit=False)
            database.init_db(cls.test_engine)
            cls.client = TestClient(app)

        @classmethod
        def tearDownClass(cls) -> None:
            database.SessionFactory = cls.original_factory
            database.engine = cls.original_engine

        def test_enqueue_list_and_approve(self) -> None:
            event = {
                "event": {
                    "source_type": "email",
                    "untrusted_content": "Potentially dangerous content",
                    "risk_score": 88,
                    "policy_action": "quarantine",
                    "approval_status": "pending",
                }
            }
            created = self.client.post("/quarantine", json=event)
            self.assertEqual(created.status_code, 201)
            event_id = created.json()["event_id"]
            self.assertEqual(self.client.get("/quarantine").status_code, 200)
            approved = self.client.post(f"/quarantine/{event_id}/approve", json={"reviewer": "analyst@example.com"})
            self.assertEqual(approved.status_code, 200)
            self.assertEqual(approved.json()["status"], "approved")

        def test_double_review_is_conflict(self) -> None:
            event = {
                "event": {
                    "source_type": "file",
                    "untrusted_content": "Review me",
                    "risk_score": 50,
                    "policy_action": "quarantine",
                    "approval_status": "pending",
                }
            }
            event_id = self.client.post("/quarantine", json=event).json()["event_id"]
            self.client.post(f"/quarantine/{event_id}/reject", json={"reviewer": "analyst"})
            response = self.client.post(f"/quarantine/{event_id}/approve", json={"reviewer": "analyst"})
            self.assertEqual(response.status_code, 409)

    unittest.main()
