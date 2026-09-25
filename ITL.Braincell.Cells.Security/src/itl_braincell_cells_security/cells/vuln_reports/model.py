"""VulnReport SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, Float, JSON, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class VulnReport(Base, TimestampMixin, RetentionMixin):
    """A vulnerability report — CVE/finding tracked from discovery through remediation."""

    __tablename__ = "vuln_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    cve_id = Column(String, nullable=True)                   # e.g. CVE-2026-12345
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)                 # critical / high / medium / low
    affected_component = Column(String, nullable=True)
    affected_versions = Column(JSON, nullable=True, default=list)
    status = Column(String, nullable=True, default="open")   # open / triaged / remediated / accepted_risk / false_positive
    discovered_by = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True, default=list)
    meta_data = Column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return f"<VulnReport id={self.id} cve_id={self.cve_id} severity={self.severity}>"
