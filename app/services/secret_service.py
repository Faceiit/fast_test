from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.encryption import decrypt_secret_value, encrypt_secret_value
from app.models.secrets import AccessPolicy, Secret, SecretVersion
from app.repositories.identity import get_principal_by_id
from app.repositories.secrets import (
    create_access_policy,
    get_current_secret_version,
    get_next_secret_version_number,
    get_secret_by_path,
    has_secret_capability,
)
from app.services.audit_service import write_audit_event
from app.services.auth_service import AuthenticatedPrincipal


OWNER_CAPABILITIES = ["read", "update", "delete", "rotate", "manage_policy"]


class SecretAlreadyExistsError(Exception):
    pass


class SecretNotFoundError(Exception):
    pass


class SecretAccessDeniedError(Exception):
    pass


class TargetPrincipalNotFoundError(Exception):
    pass


def create_secret(
    db: Session,
    path: str,
    value: str,
    description: str | None,
    expires_at: datetime | None,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> Secret:
    existing_secret = get_secret_by_path(db, path)

    if existing_secret is not None:
        write_audit_event(
            db=db,
            actor=current_principal,
            action="secret.created",
            status="denied",
            request=request,
        )
        db.commit()
        raise SecretAlreadyExistsError

    secret = Secret(
        path=path,
        description=description,
        owner_principal_id=current_principal.id,
        current_version=1,
    )

    db.add(secret)
    db.flush()

    secret_version = SecretVersion(
        secret_id=secret.id,
        version=1,
        ciphertext=encrypt_secret_value(value),
        key_version=settings.encryption_key_version,
        created_by=current_principal.id,
        expires_at=expires_at,
    )

    db.add(secret_version)

    for capability in OWNER_CAPABILITIES:
        create_access_policy(
            db=db,
            principal_id=current_principal.id,
            secret_id=secret.id,
            capability=capability,
            created_by=current_principal.id,
        )

    write_audit_event(
        db=db,
        actor=current_principal,
        action="secret.created",
        status="success",
        secret_id=secret.id,
        request=request,
    )

    db.commit()
    db.refresh(secret)

    return secret


def read_secret_value(
    db: Session,
    path: str,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> tuple[Secret, SecretVersion, str]:
    secret = get_secret_by_path(db, path)

    if secret is None:
        raise SecretNotFoundError

    if not has_secret_capability(db, secret, current_principal.id, "read"):
        write_audit_event(
            db=db,
            actor=current_principal,
            action="secret.read",
            status="denied",
            secret_id=secret.id,
            request=request,
        )
        db.commit()
        raise SecretAccessDeniedError

    secret_version = get_current_secret_version(db, secret)

    if secret_version is None:
        raise SecretNotFoundError

    if secret_version.expires_at is not None:
        now = datetime.now(timezone.utc)

        if secret_version.expires_at <= now:
            write_audit_event(
                db=db,
                actor=current_principal,
                action="secret.read",
                status="denied",
                secret_id=secret.id,
                request=request,
            )
            db.commit()
            raise SecretAccessDeniedError

    plaintext = decrypt_secret_value(secret_version.ciphertext)

    write_audit_event(
        db=db,
        actor=current_principal,
        action="secret.read",
        status="success",
        secret_id=secret.id,
        request=request,
    )

    db.commit()

    return secret, secret_version, plaintext


def rotate_secret_value(
    db: Session,
    path: str,
    value: str,
    expires_at: datetime | None,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> Secret:
    secret = get_secret_by_path(db, path)

    if secret is None:
        raise SecretNotFoundError

    if not has_secret_capability(db, secret, current_principal.id, "rotate"):
        write_audit_event(
            db=db,
            actor=current_principal,
            action="secret.rotated",
            status="denied",
            secret_id=secret.id,
            request=request,
        )
        db.commit()
        raise SecretAccessDeniedError

    next_version = get_next_secret_version_number(db, secret.id)

    secret_version = SecretVersion(
        secret_id=secret.id,
        version=next_version,
        ciphertext=encrypt_secret_value(value),
        key_version=settings.encryption_key_version,
        created_by=current_principal.id,
        expires_at=expires_at,
    )

    secret.current_version = next_version
    secret.updated_at = datetime.now(timezone.utc)

    db.add(secret_version)
    db.add(secret)

    write_audit_event(
        db=db,
        actor=current_principal,
        action="secret.rotated",
        status="success",
        secret_id=secret.id,
        request=request,
    )

    db.commit()
    db.refresh(secret)

    return secret


def delete_secret(
    db: Session,
    path: str,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> None:
    secret = get_secret_by_path(db, path)

    if secret is None:
        raise SecretNotFoundError

    if not has_secret_capability(db, secret, current_principal.id, "delete"):
        write_audit_event(
            db=db,
            actor=current_principal,
            action="secret.deleted",
            status="denied",
            secret_id=secret.id,
            request=request,
        )
        db.commit()
        raise SecretAccessDeniedError

    secret.is_deleted = True
    secret.updated_at = datetime.now(timezone.utc)
    db.add(secret)

    write_audit_event(
        db=db,
        actor=current_principal,
        action="secret.deleted",
        status="success",
        secret_id=secret.id,
        request=request,
    )

    db.commit()


def grant_secret_access(
    db: Session,
    secret_path: str,
    target_principal_id,
    capability: str,
    current_principal: AuthenticatedPrincipal,
    request: Request | None = None,
) -> AccessPolicy:
    secret = get_secret_by_path(db, secret_path)

    if secret is None:
        raise SecretNotFoundError

    can_manage_policy = (
        "admin" in current_principal.roles
        or has_secret_capability(db, secret, current_principal.id, "manage_policy")
    )

    if not can_manage_policy:
        write_audit_event(
            db=db,
            actor=current_principal,
            action="policy.created",
            status="denied",
            secret_id=secret.id,
            request=request,
        )
        db.commit()
        raise SecretAccessDeniedError

    target_principal = get_principal_by_id(db, target_principal_id)

    if target_principal is None or not target_principal.is_active:
        raise TargetPrincipalNotFoundError

    policy = create_access_policy(
        db=db,
        principal_id=target_principal_id,
        secret_id=secret.id,
        capability=capability,
        created_by=current_principal.id,
    )

    write_audit_event(
        db=db,
        actor=current_principal,
        action="policy.created",
        status="success",
        secret_id=secret.id,
        request=request,
    )

    db.commit()
    db.refresh(policy)

    return policy