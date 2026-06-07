import uuid
from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.audit_actions import AuditAction, AuditStatus
from app.core.datetime import utc_now
from app.core.security import get_api_key_prefix, verify_api_key, verify_password
from app.models.identity import Principal
from app.repositories.identity import (
    get_principal_by_id,
    get_roles_for_principal,
    get_service_account_by_api_key_prefix,
    get_user_by_username,
    update_service_account_last_used,
)
from app.services.audit_service import write_audit_event


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    id: uuid.UUID
    principal_type: str
    display_name: str
    roles: list[str]


def authenticate_user(
    db: Session,
    username: str,
    password: str,
    request: Request | None = None,
) -> AuthenticatedPrincipal | None:
    user = get_user_by_username(db, username)

    if user is None:
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_LOGIN,
            status=AuditStatus.FAILED,
            request=request,
        )
        db.commit()
        return None

    principal = get_principal_by_id(db, user.principal_id)

    if principal is None or not principal.is_active:
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_LOGIN,
            status=AuditStatus.DENIED,
            request=request,
        )
        db.commit()
        return None

    if not verify_password(password, user.password_hash):
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_LOGIN,
            status=AuditStatus.FAILED,
            request=request,
        )
        db.commit()
        return None

    user.last_login_at = utc_now()
    db.add(user)

    roles = get_roles_for_principal(db, principal.id)

    authenticated_principal = AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )

    write_audit_event(
        db=db,
        actor=authenticated_principal,
        action=AuditAction.AUTH_LOGIN,
        status=AuditStatus.SUCCESS,
        request=request,
    )

    db.commit()

    return authenticated_principal


def authenticate_api_key(
    db: Session,
    api_key: str,
    request: Request | None = None,
) -> AuthenticatedPrincipal | None:
    api_key_prefix = get_api_key_prefix(api_key)

    if api_key_prefix is None:
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_API_KEY,
            status=AuditStatus.FAILED,
            request=request,
        )
        db.commit()
        return None

    service_account = get_service_account_by_api_key_prefix(db, api_key_prefix)

    if service_account is None:
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_API_KEY,
            status=AuditStatus.FAILED,
            request=request,
        )
        db.commit()
        return None

    if service_account.expires_at is not None and service_account.expires_at <= utc_now():
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_API_KEY,
            status=AuditStatus.DENIED,
            request=request,
        )
        db.commit()
        return None

    if not verify_api_key(api_key, service_account.api_key_hash):
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_API_KEY,
            status=AuditStatus.FAILED,
            request=request,
        )
        db.commit()
        return None

    principal = get_principal_by_id(db, service_account.principal_id)

    if principal is None or not principal.is_active:
        write_audit_event(
            db=db,
            actor=None,
            action=AuditAction.AUTH_API_KEY,
            status=AuditStatus.DENIED,
            request=request,
        )
        db.commit()
        return None

    update_service_account_last_used(db, service_account)

    roles = get_roles_for_principal(db, principal.id)

    authenticated_principal = AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )

    write_audit_event(
        db=db,
        actor=authenticated_principal,
        action=AuditAction.AUTH_API_KEY,
        status=AuditStatus.SUCCESS,
        request=request,
    )

    db.commit()

    return authenticated_principal


def build_authenticated_principal_from_jwt(
    db: Session,
    principal_id: uuid.UUID,
) -> AuthenticatedPrincipal | None:
    principal: Principal | None = get_principal_by_id(db, principal_id)

    if principal is None or not principal.is_active:
        return None

    roles = get_roles_for_principal(db, principal.id)

    return AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )