from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.secrets import AuditLog


def list_audit_logs(db: Session, limit: int = 100) -> list[AuditLog]:
    statement = (
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )

    return list(db.scalars(statement).all())