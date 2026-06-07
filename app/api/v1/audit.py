import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies import require_roles
from app.core.datetime import ensure_aware_utc
from app.db.dependencies import get_db
from app.repositories.audit import list_audit_logs
from app.schemas.audit import AuditLogResponse
from app.services.auth_service import AuthenticatedPrincipal


router = APIRouter(prefix="/audit", tags=["audit"])


def normalize_query_datetime(value: datetime | None, field_name: str) -> datetime | None:
    try:
        return ensure_aware_utc(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field_name} must be timezone-aware",
        ) from exc


@router.get("", response_model=list[AuditLogResponse])
def list_audit_logs_endpoint(
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_roles("admin", "auditor")),
    ],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    actor_id: uuid.UUID | None = None,
    secret_id: uuid.UUID | None = None,
    action: str | None = None,
    status: str | None = None,
    request_id: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> list[AuditLogResponse]:
    audit_logs = list_audit_logs(
        db=db,
        limit=limit,
        actor_id=actor_id,
        secret_id=secret_id,
        action=action,
        status=status,
        request_id=request_id,
        created_from=normalize_query_datetime(created_from, "created_from"),
        created_to=normalize_query_datetime(created_to, "created_to"),
    )

    return [
        AuditLogResponse(
            id=audit_log.id,
            actor_type=audit_log.actor_type,
            actor_id=audit_log.actor_id,
            action=audit_log.action,
            status=audit_log.status,
            secret_id=audit_log.secret_id,
            ip_address=audit_log.ip_address,
            user_agent=audit_log.user_agent,
            request_id=audit_log.request_id,
            created_at=audit_log.created_at,
        )
        for audit_log in audit_logs
    ]