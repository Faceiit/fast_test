from datetime import datetime

from sqlalchemy.orm import Session

from app.core.security import generate_api_key, hash_api_key
from app.models.identity import Principal, ServiceAccount
from app.repositories.identity import assign_role_to_principal, ensure_role
from app.services.auth_service import AuthenticatedPrincipal


def create_service_account(
    db: Session,
    name: str,
    expires_at: datetime | None,
    current_principal: AuthenticatedPrincipal,
) -> tuple[ServiceAccount, str]:
    raw_api_key, api_key_prefix = generate_api_key()

    principal = Principal(
        principal_type="service_account",
        display_name=name,
    )

    db.add(principal)
    db.flush()

    service_account = ServiceAccount(
        principal_id=principal.id,        # Привязываем к созданному выше паспорту
        name=name,                        # Имя робота (например, "Скрипт бэкапа")
        api_key_prefix=api_key_prefix,    # Публичный префикс для быстрого поиска
        api_key_hash=hash_api_key(raw_api_key), # ХЭШИРУЕМ секретную часть
        owner_principal_id=current_principal.id, # Лог аудита: ID админа, который создал бота
        expires_at=expires_at,            # Срок годности
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

    db.commit()
    db.refresh(service_account)

    return service_account, raw_api_key