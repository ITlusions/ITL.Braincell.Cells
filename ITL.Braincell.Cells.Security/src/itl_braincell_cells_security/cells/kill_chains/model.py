"""KillChain SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, JSON, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class KillChain(Base, TimestampMixin, RetentionMixin):
    """Attack kill chain — an ordered sequence of MITRE ATT&CK stages for a
    specific incident or threat actor campaign (recon -> weaponize -> ... -> impact)."""

    __tablename__ = "kill_chains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    incident_id = Column(UUID(as_uuid=True), nullable=True)      # optional link to security_incidents.id
    threat_actor_name = Column(String, nullable=True)
    stages = Column(JSON, nullable=True, default=list)            # ordered list of {stage, ttp_id, description, timestamp}
    status = Column(String, nullable=True, default="active")      # active / mitigated / archived
    meta_data = Column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return f"<KillChain id={self.id} title={self.title!r} status={self.status}>"
