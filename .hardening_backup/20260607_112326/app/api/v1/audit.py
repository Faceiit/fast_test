from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.v1.dependencies import require_roles
from app.db.dependencies import get_db
from app.repositories.audit import list_audit_logs
from app.schemas.audit import AuditLogResponse
from app.services.auth_service import AuthenticatedPrincipal


router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogResponse])
def list_audit_logs_endpoint(
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_roles("admin", "auditor")),
    ],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditLogResponse]:
    audit_logs = list_audit_logs(db=db, limit=limit)

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
