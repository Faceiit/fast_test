import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Capability = Literal["read", "create", "update", "delete", "rotate", "manage_policy"]


class SecretCreateRequest(BaseModel):
    path: str = Field(
        min_length=3,
        max_length=512,
        pattern=r"^[a-zA-Z0-9._/\-]+$",
    )
    value: str = Field(min_length=1, max_length=10000)
    description: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None


class SecretRotateRequest(BaseModel):
    value: str = Field(min_length=1, max_length=10000)
    expires_at: datetime | None = None


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
    secret_path: str = Field(min_length=3, max_length=512)
    principal_id: uuid.UUID
    capability: Capability


class AccessPolicyResponse(BaseModel):
    id: uuid.UUID
    principal_id: uuid.UUID
    secret_id: uuid.UUID
    capability: str
    created_by: uuid.UUID | None
    created_at: datetime