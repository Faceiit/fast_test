from datetime import datetime

from fastapi import Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit_actions import AuditAction, AuditStatus
from app.core.datetime import ensure_aware_utc
from app.core.security import generate_api_key, hash_api_key
from app.models.identity import Principal, PrincipalType, ServiceAccount
from app.repositories.identity import assign_role_to_principal, ensure_role
from app.services.audit_service import write_audit_event
from app.services.auth_service import AuthenticatedPrincipal


class ServiceAccountAlreadyExistsError(Exception):
    pass


def create_service_account(
    db: Session,
    name: str,
    expires_at: datetime | None,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> tuple[ServiceAccount, str]:
    normalized_name = name.strip()
    expires_at = ensure_aware_utc(expires_at)

    raw_api_key, api_key_prefix = generate_api_key()

    principal = Principal(
        principal_type=PrincipalType.SERVICE_ACCOUNT.value,
        display_name=normalized_name,
    )
    db.add(principal)
    db.flush()

    service_account = ServiceAccount(
        principal_id=principal.id,
        name=normalized_name,
        api_key_prefix=api_key_prefix,
        api_key_hash=hash_api_key(raw_api_key),
        owner_principal_id=current_principal.id,
        expires_at=expires_at,
    )
    db.add(service_account)

    service_role = ensure_role(
        db,
        name="service",
        description="Service account role",
    )
    assign_role_to_principal(
        db,
        principal_id=principal.id,
        role_id=service_role.id,
        granted_by=current_principal.id,
    )

    write_audit_event(
        db=db,
        actor=current_principal,
        action=AuditAction.SERVICE_ACCOUNT_CREATED,
        status=AuditStatus.SUCCESS,
        request=request,
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ServiceAccountAlreadyExistsError from exc

    db.refresh(service_account)
    return service_account, raw_api_key
