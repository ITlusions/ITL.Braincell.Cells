"""KillChain Pydantic schemas"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class KillChainCreate(BaseModel):
    title: str
    description: str | None = None
    incident_id: UUID | None = None
    threat_actor_name: str | None = None
    stages: list[dict[str, Any]] | None = None
    status: str | None = "active"
    meta_data: dict[str, Any] | None = None


class KillChainResponse(BaseModel):
    id: UUID
    title: str
    description: str | None = None
    incident_id: UUID | None = None
    threat_actor_name: str | None = None
    stages: list[dict[str, Any]] | None = None
    status: str | None = None
    meta_data: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
