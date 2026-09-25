"""IOC Pydantic schemas"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    severity: str | None = None
    status: str | None = "active"
    source: str | None = None
    context: str | None = None
    tags: list[str] | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    meta_data: dict[str, Any] | None = None


class IOCResponse(BaseModel):
    id: UUID
    ioc_type: str
    value: str
    severity: str | None = None
    status: str | None = None
    source: str | None = None
    context: str | None = None
    tags: list[str] | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    meta_data: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
