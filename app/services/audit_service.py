import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.secrets import AuditLog
from app.services.auth_service import AuthenticatedPrincipal


def write_audit_event(
    db: Session,
    actor: AuthenticatedPrincipal | None,
    action: str,
    status: str,
    secret_id: uuid.UUID | None = None,
    request: Request | None = None,
) -> None:
    ip_address = None
    user_agent = None
    request_id = None

    if request is not None:
        ip_address = request.client.host if request.client is not None else None
        user_agent = request.headers.get("user-agent")
        request_id = getattr(request.state, "request_id", None)
        if request_id is None:
            request_id = request.headers.get("x-request-id")

    db.add(
        AuditLog(
            actor_type=actor.principal_type if actor is not None else "anonymous",
            actor_id=actor.id if actor is not None else None,
            action=action,
            status=status,
            secret_id=secret_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )
    )
