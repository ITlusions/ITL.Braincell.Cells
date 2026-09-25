"""IntelReport Pydantic schemas"""
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class IntelReportCreate(BaseModel):
    title: str
    summary: str | None = None
    content: str | None = None
    classification_level: str | None = None
    tlp_level: str | None = None
    source: str | None = None
    analyst: str | None = None


class IntelReportResponse(BaseModel):
    id: UUID
    title: str
    summary: str | None = None
    content: str | None = None
    classification_level: str | None = None
    tlp_level: str | None = None
    source: str | None = None
    analyst: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
