"""SecurityIncident Pydantic schemas"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class SecurityIncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: str | None = None
    status: str | None = "open"
    attack_vector: str | None = None
    threat_actor_name: str | None = None
    mitre_tactics: list[str] | None = None
    classification_level: str | None = None
    detected_at: datetime | None = None
    resolved_at: datetime | None = None
    meta_data: dict[str, Any] | None = None


class SecurityIncidentResponse(BaseModel):
    id: UUID
    title: str
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    attack_vector: str | None = None
    threat_actor_name: str | None = None
    mitre_tactics: list[str] | None = None
    classification_level: str | None = None
    detected_at: datetime | None = None
    resolved_at: datetime | None = None
    meta_data: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
