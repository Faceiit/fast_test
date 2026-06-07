import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.secrets import AuditLog


def list_audit_logs(
    db: Session,
    limit: int = 100,
    actor_id: uuid.UUID | None = None,
    secret_id: uuid.UUID | None = None,
    action: str | None = None,
    status: str | None = None,
    request_id: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> list[AuditLog]:
    statement = select(AuditLog)

    if actor_id is not None:
        statement = statement.where(AuditLog.actor_id == actor_id)
    if secret_id is not None:
        statement = statement.where(AuditLog.secret_id == secret_id)
    if action is not None:
        statement = statement.where(AuditLog.action == action)
    if status is not None:
        statement = statement.where(AuditLog.status == status)
    if request_id is not None:
        statement = statement.where(AuditLog.request_id == request_id)
    if created_from is not None:
        statement = statement.where(AuditLog.created_at >= created_from)
    if created_to is not None:
        statement = statement.where(AuditLog.created_at <= created_to)

    statement = statement.order_by(AuditLog.created_at.desc()).limit(limit)
    return list(db.scalars(statement).all())
