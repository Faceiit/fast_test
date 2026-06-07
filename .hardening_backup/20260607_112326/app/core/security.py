import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import settings


password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(
    principal_id: uuid.UUID,
    principal_type: str,
    roles: list[str],
) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
    
    payload: dict[str, Any] = {
        "sub": str(principal_id),   # Кому выдан (ID субъекта)
        "type": principal_type,     # Тип ('user' или 'service_account')
        "roles": roles,             # Список ролей (например, ['admin'])
        "iat": int(now.timestamp()), # Время выдачи токена (Issued At)
        "exp": int(expires_at.timestamp()), # Время окончания действия (Expiration)
        "iss": settings.app_name,   # Кто выдал токен (Issuer)
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any] | None:
    # Функция jwt.decode автоматически проверяет всё: не истекло ли время "exp", совпадает ли "iss", не подделана ли цифровая подпись
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.app_name,
        )
    except InvalidTokenError:
        return None


def generate_api_key() -> tuple[str, str]:
    public_part = secrets.token_hex(4)     # 8 символов (например: 'a1b2c3d4')
    secret_part = secrets.token_urlsafe(32) # Длинный случайный криптографический хвост

    prefix = f"smsk_live_{public_part}"    # Префикс, например: 'smsk_live_a1b2c3d4'
    raw_api_key = f"{prefix}.{secret_part}" # Полный ключ: 'smsk_live_a1b2c3d4.xxxx...'

    return raw_api_key, prefix


def get_api_key_prefix(api_key: str) -> str | None:
    if "." not in api_key:
        return None

    prefix, _ = api_key.split(".", maxsplit=1)

    if not prefix.startswith("smsk_live_"):
        return None

    return prefix


def hash_api_key(api_key: str) -> str:
    return hmac.new(
        settings.api_key_pepper.encode("utf-8"),
        api_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_api_key(api_key: str, expected_hash: str) -> bool:
    actual_hash = hash_api_key(api_key)
    return hmac.compare_digest(actual_hash, expected_hash)