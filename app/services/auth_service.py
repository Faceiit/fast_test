import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.security import get_api_key_prefix, verify_api_key, verify_password
from app.models.identity import Principal
from app.repositories.identity import (
    get_principal_by_id,
    get_roles_for_principal,
    get_service_account_by_api_key_prefix,
    get_user_by_username,
    update_service_account_last_used,
)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    id: uuid.UUID
    principal_type: str
    display_name: str
    roles: list[str]


def authenticate_user(db: Session, username: str, password: str) -> AuthenticatedPrincipal | None:
    # 1. Ищем пользователя по логину (без учета регистра)
    user = get_user_by_username(db, username)
    if user is None:
        return None  # Пользователя нет -> тихо выходим

    # 2. Ищем его базовый "паспорт" субъекта
    principal = get_principal_by_id(db, user.principal_id)
    
    # 3. Проверяем, существует ли он вообще и не забанен ли (is_active)
    if principal is None or not principal.is_active:
        return None  # Аккаунт удален или заблокирован

    # 4. Проверяем пароль через безопасный хешер Argon2/Bcrypt
    if not verify_password(password, user.password_hash):
        return None  # Неверный пароль

     # 5. Если всё ок, фиксируем время успешного входа
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit() # Сохраняем дату входа в БД

    # 6. Собираем его роли и возвращаем готовый объект
    roles = get_roles_for_principal(db, principal.id)

    return AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )


def authenticate_api_key(db: Session, api_key: str) -> AuthenticatedPrincipal | None:
    # 1. Отрезаем префикс (например: smsk_live_a1b2c3d4)
    api_key_prefix = get_api_key_prefix(api_key)
    if api_key_prefix is None:
        return None # Ключ явно сломан или подделан

    # 2. Мгновенно вытаскиваем робота из БД по короткому префиксу
    service_account = get_service_account_by_api_key_prefix(db, api_key_prefix)
    if service_account is None:
        return None # Робот с таким префиксом не существует

    # 3. Проверяем срок годности ключа (если он задан)
    if service_account.expires_at is not None:
        now = datetime.now(timezone.utc)
        if service_account.expires_at <= now:
            return None  # Срок действия ключа истёк

    # 4. Финальный рубеж: проверяем секретную часть через HMAC-SHA256 и compare_digest
    if not verify_api_key(api_key, service_account.api_key_hash):
        return None  # Ключ подделан или изменен

    # 5. Проверяем, не заблокирован ли этот сервисный аккаунт
    principal = get_principal_by_id(db, service_account.principal_id)
    if principal is None or not principal.is_active:
        return None

    # 6. Обновляем поле last_used_at (админ увидит, что бот активен)
    update_service_account_last_used(db, service_account)
    db.commit()

    # 7. Вытаскиваем роли робота и пускаем его в систему
    roles = get_roles_for_principal(db, principal.id)

    return AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )


def build_authenticated_principal_from_jwt(db: Session, principal_id: uuid.UUID) -> AuthenticatedPrincipal | None:
    # 1. Из JWT-токена мы достали principal_id. Идем в базу проверить субъекта.
    principal: Principal | None = get_principal_by_id(db, principal_id)

    # 2. Проверяем, жив ли аккаунт
    if principal is None or not principal.is_active:
        return None # Если админ забанил юзера, его JWT-токен мгновенно перестанет работать

    # 3. Подтягиваем актуальный список ролей из базы данных
    roles = get_roles_for_principal(db, principal.id)

    return AuthenticatedPrincipal(
        id=principal.id,
        principal_type=principal.principal_type,
        display_name=principal.display_name,
        roles=roles,
    )