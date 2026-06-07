import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.core.datetime import ensure_aware_utc


class ServiceAccountCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Service account name cannot be empty")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime | None) -> datetime | None:
        return ensure_aware_utc(value)


class ServiceAccountCreateResponse(BaseModel):
    principal_id: uuid.UUID
    name: str
    api_key: str
    api_key_prefix: str
    warning: str = "Save this API key now. It will not be shown again."
