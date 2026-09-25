"""VulnReport Pydantic schemas"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class VulnReportCreate(BaseModel):
    title: str
    description: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    affected_component: str | None = None
    affected_versions: list[str] | None = None
    status: str | None = "open"
    discovered_by: str | None = None
    remediation: str | None = None
    references: list[str] | None = None
    meta_data: dict[str, Any] | None = None


class VulnReportResponse(BaseModel):
    id: UUID
    title: str
    description: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    affected_component: str | None = None
    affected_versions: list[str] | None = None
    status: str | None = None
    discovered_by: str | None = None
    remediation: str | None = None
    references: list[str] | None = None
    meta_data: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
