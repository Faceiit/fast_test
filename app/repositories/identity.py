import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.datetime import utc_now
from app.models.identity import Principal, PrincipalRole, Role, ServiceAccount, User


def normalize_role_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("Role name cannot be empty")
    return normalized


def get_principal_by_id(db: Session, principal_id: uuid.UUID) -> Principal | None:
    return db.get(Principal, principal_id)


def get_user_by_username(db: Session, username: str) -> User | None:
    normalized_username = username.strip().lower()
    statement = select(User).where(func.lower(User.username) == normalized_username)
    return db.scalar(statement)


def get_roles_for_principal(db: Session, principal_id: uuid.UUID) -> list[str]:
    statement = (
        select(Role.name)
        .join(PrincipalRole, PrincipalRole.role_id == Role.id)
        .where(PrincipalRole.principal_id == principal_id)
    )
    return list(db.scalars(statement).all())


def get_role_by_name(db: Session, name: str) -> Role | None:
    normalized_name = normalize_role_name(name)
    statement = select(Role).where(func.lower(Role.name) == normalized_name)
    return db.scalar(statement)


def ensure_role(db: Session, name: str, description: str | None = None) -> Role:
    normalized_name = normalize_role_name(name)

    role = get_role_by_name(db, normalized_name)
    if role is not None:
        return role

    role = Role(name=normalized_name, description=description)
    db.add(role)
    db.flush()
    return role


def assign_role_to_principal(
    db: Session,
    principal_id: uuid.UUID,
    role_id: uuid.UUID,
    granted_by: uuid.UUID | None = None,
) -> None:
    existing = db.get(
        PrincipalRole,
        {"principal_id": principal_id, "role_id": role_id},
    )
    if existing is not None:
        return

    db.add(
        PrincipalRole(
            principal_id=principal_id,
            role_id=role_id,
            granted_by=granted_by,
        )
    )


def get_service_account_by_api_key_prefix(
    db: Session,
    api_key_prefix: str,
) -> ServiceAccount | None:
    statement = select(ServiceAccount).where(
        ServiceAccount.api_key_prefix == api_key_prefix
    )
    return db.scalar(statement)


def update_service_account_last_used(
    db: Session,
    service_account: ServiceAccount,
) -> None:
    service_account.last_used_at = utc_now()
    db.add(service_account)
