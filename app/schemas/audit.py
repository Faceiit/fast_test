import uuid
from datetime import datetime

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    actor_type: str
    actor_id: uuid.UUID | None
    action: str
    status: str
    secret_id: uuid.UUID | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    created_at: datetime