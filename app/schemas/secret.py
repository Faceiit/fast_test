import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.datetime import ensure_aware_utc


SECRET_PATH_PATTERN = r"^[a-zA-Z0-9._/\-]+$"

SecretPath = Annotated[
    str,
    Field(
        min_length=3,
        max_length=512,
        pattern=SECRET_PATH_PATTERN,
    ),
]

Capability = Literal[
    "read",
    "delete",
    "rotate",
    "manage_policy",
]


class SecretCreateRequest(BaseModel):
    path: SecretPath
    value: str = Field(min_length=1, max_length=10000)
    description: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime | None) -> datetime | None:
        return ensure_aware_utc(value)


class SecretRotateRequest(BaseModel):
    value: str = Field(min_length=1, max_length=10000)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime | None) -> datetime | None:
        return ensure_aware_utc(value)


class SecretMetadataResponse(BaseModel):
    id: uuid.UUID
    path: str
    description: str | None
    owner_principal_id: uuid.UUID
    current_version: int
    created_at: datetime
    updated_at: datetime


class SecretValueResponse(BaseModel):
    id: uuid.UUID
    path: str
    description: str | None
    current_version: int
    value: str
    expires_at: datetime | None


class AccessPolicyCreateRequest(BaseModel):
    secret_path: SecretPath
    principal_id: uuid.UUID
    capability: Capability


class AccessPolicyResponse(BaseModel):
    id: uuid.UUID
    principal_id: uuid.UUID
    secret_id: uuid.UUID
    capability: str
    created_by: uuid.UUID | None
    created_at: datetime