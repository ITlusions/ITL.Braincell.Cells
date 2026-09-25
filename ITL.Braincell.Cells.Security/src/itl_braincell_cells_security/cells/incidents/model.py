"""SecurityIncident SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, DateTime, JSON, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class SecurityIncident(Base, TimestampMixin, RetentionMixin):
    __tablename__ = "security_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)               # critical / high / medium / low
    status = Column(String, nullable=True, default="open")  # open / investigating / contained / resolved / closed
    attack_vector = Column(String, nullable=True)           # initial attack vector
    threat_actor_name = Column(String, nullable=True)       # attributed threat actor
    mitre_tactics = Column(JSON, nullable=True, default=list)  # MITRE ATT&CK tactic IDs
    classification_level = Column(String, nullable=True)    # classification marking
    detected_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    meta_data = Column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return f"<SecurityIncident id={self.id} title={self.title!r} severity={self.severity}>"
