import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import settings


password_hash = PasswordHash.recommended()
API_KEY_PREFIX_RE = re.compile(r"^smsk_live_[a-f0-9]{16}$")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(
    principal_id: uuid.UUID,
    principal_type: str,
) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": str(principal_id),
        "type": principal_type,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.app_name,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any] | None:
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
    public_part = secrets.token_hex(8)
    secret_part = secrets.token_urlsafe(32)
    prefix = f"smsk_live_{public_part}"
    raw_api_key = f"{prefix}.{secret_part}"
    return raw_api_key, prefix


def get_api_key_prefix(api_key: str) -> str | None:
    prefix, separator, secret_part = api_key.partition(".")

    if separator != "." or not secret_part:
        return None

    if API_KEY_PREFIX_RE.fullmatch(prefix) is None:
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
