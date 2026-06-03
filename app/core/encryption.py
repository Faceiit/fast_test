from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


class EncryptionConfigError(RuntimeError):
    pass


class DecryptionError(RuntimeError):
    pass


@lru_cache
def get_fernet() -> Fernet:
    key_path = Path(settings.master_key_file)

    if not key_path.exists():
        raise EncryptionConfigError(
            f"Master key file does not exist: {settings.master_key_file}"
        )

    key = key_path.read_text(encoding="utf-8").strip()

    if not key:
        raise EncryptionConfigError("Master key file is empty")

    try:
        return Fernet(key.encode("utf-8"))
    except ValueError as exc:
        raise EncryptionConfigError("Master key is not a valid Fernet key") from exc


def encrypt_secret_value(plaintext: str) -> str:
    token = get_fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret_value(ciphertext: str) -> str:
    try:
        plaintext = get_fernet().decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise DecryptionError("Secret ciphertext cannot be decrypted") from exc

    return plaintext.decode("utf-8")