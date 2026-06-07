import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ServiceAccountCreateRequest(BaseModel): # Используется, когда администратор хочет выпустить новый API-ключ
    name: str = Field(min_length=3, max_length=255)
    expires_at: datetime | None = None #  дата и время, когда ключ автоматически перестанет работать. По умолчанию `None` (бессрочный ключ)


class ServiceAccountCreateResponse(BaseModel): # вывод результата создания ключа
    principal_id: uuid.UUID
    name: str
    api_key: str          # Полный сырой ключ: smsk_live_a1b2c3d4.secret_xyz123...
    api_key_prefix: str   # Только префикс: smsk_live_a1b2c3d4
    warning: str = "Save this API key now. It will not be shown again."