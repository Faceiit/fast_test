import uuid

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.models.secrets import AccessPolicy, Secret, SecretVersion


def get_secret_by_path(db: Session, path: str) -> Secret | None:
    statement = select(Secret).where(
        Secret.path == path,
        Secret.is_deleted.is_(False),
    )

    return db.scalar(statement)


def get_current_secret_version(
    db: Session,
    secret: Secret,
) -> SecretVersion | None:
    statement = select(SecretVersion).where(
        SecretVersion.secret_id == secret.id,
        SecretVersion.version == secret.current_version,
    )

    return db.scalar(statement)


def get_next_secret_version_number(db: Session, secret_id: uuid.UUID) -> int:
    statement = select(
        func.coalesce(func.max(SecretVersion.version), 0) + 1
    ).where(SecretVersion.secret_id == secret_id)

    return int(db.scalar(statement) or 1)


def has_secret_capability(
    db: Session,
    secret: Secret,
    principal_id: uuid.UUID,
    capability: str,
) -> bool:
    if secret.owner_principal_id == principal_id:
        return True

    statement = select(AccessPolicy.id).where(
        AccessPolicy.principal_id == principal_id,
        AccessPolicy.secret_id == secret.id,
        AccessPolicy.capability == capability,
    )

    return db.scalar(statement) is not None


def list_accessible_secrets(
    db: Session,
    principal_id: uuid.UUID,
    can_see_all_metadata: bool = False,
) -> list[Secret]:
    if can_see_all_metadata:
        statement = (
            select(Secret)
            .where(Secret.is_deleted.is_(False))
            .order_by(Secret.path)
        )

        return list(db.scalars(statement).all())

    statement = (
        select(Secret)
        .outerjoin(
            AccessPolicy,
            and_(
                AccessPolicy.secret_id == Secret.id,
                AccessPolicy.principal_id == principal_id,
                AccessPolicy.capability == "read",
            ),
        )
        .where(
            Secret.is_deleted.is_(False),
            or_(
                Secret.owner_principal_id == principal_id,
                AccessPolicy.id.is_not(None),
            ),
        )
        .order_by(Secret.path)
    )

    return list(db.scalars(statement).unique().all())


def get_access_policy(
    db: Session,
    principal_id: uuid.UUID,
    secret_id: uuid.UUID,
    capability: str,
) -> AccessPolicy | None:
    statement = select(AccessPolicy).where(
        AccessPolicy.principal_id == principal_id,
        AccessPolicy.secret_id == secret_id,
        AccessPolicy.capability == capability,
    )

    return db.scalar(statement)


def create_access_policy(
    db: Session,
    principal_id: uuid.UUID,
    secret_id: uuid.UUID,
    capability: str,
    created_by: uuid.UUID | None,
) -> AccessPolicy:
    existing_policy = get_access_policy(
        db=db,
        principal_id=principal_id,
        secret_id=secret_id,
        capability=capability,
    )

    if existing_policy is not None:
        return existing_policy

    policy = AccessPolicy(
        principal_id=principal_id,
        secret_id=secret_id,
        capability=capability,
        created_by=created_by,
    )

    db.add(policy)
    db.flush()

    return policy