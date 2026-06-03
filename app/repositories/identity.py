import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.identity import Principal, PrincipalRole, Role, ServiceAccount, User


def get_principal_by_id(db: Session, principal_id: uuid.UUID) -> Principal | None:
    return db.get(Principal, principal_id)


def get_user_by_username(db: Session, username: str) -> User | None:
    statement = select(User).where(func.lower(User.username) == username.lower())
    return db.scalar(statement)


def get_roles_for_principal(db: Session, principal_id: uuid.UUID) -> list[str]:
    statement = (
        select(Role.name)
        .join(PrincipalRole, PrincipalRole.role_id == Role.id)
        .where(PrincipalRole.principal_id == principal_id)
    )

    return list(db.scalars(statement).all())


def get_role_by_name(db: Session, name: str) -> Role | None:
    statement = select(Role).where(Role.name == name)
    return db.scalar(statement)


def ensure_role(db: Session, name: str, description: str | None = None) -> Role:
    role = get_role_by_name(db, name)

    if role is not None:
        return role

    role = Role(name=name, description=description)
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
        {
            "principal_id": principal_id,
            "role_id": role_id,
        },
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
    service_account.last_used_at = datetime.now(timezone.utc)
    db.add(service_account)