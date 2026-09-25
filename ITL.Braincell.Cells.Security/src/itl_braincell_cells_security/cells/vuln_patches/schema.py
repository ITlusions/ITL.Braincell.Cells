"""VulnPatch Pydantic schemas"""
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class VulnPatchCreate(BaseModel):
    title: str
    description: str | None = None
    vulnerable_code: str | None = None
    patched_code: str | None = None
    patch_explanation: str | None = None
    language: str | None = None
    category: str | None = None
    severity: str | None = None


class VulnPatchResponse(BaseModel):
    id: UUID
    title: str
    description: str | None = None
    vulnerable_code: str | None = None
    patched_code: str | None = None
    patch_explanation: str | None = None
    language: str | None = None
    category: str | None = None
    severity: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
