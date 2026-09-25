"""IntelReport SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class IntelReport(Base, TimestampMixin, RetentionMixin):
    __tablename__ = "intel_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    content = Column(Text, nullable=True)
    classification_level = Column(String, nullable=True)   # classification marking
    tlp_level = Column(String, nullable=True)               # WHITE / GREEN / AMBER / RED
    source = Column(String, nullable=True)
    analyst = Column(String, nullable=True)

    def __repr__(self) -> str:
        return f"<IntelReport id={self.id} title={self.title!r} tlp={self.tlp_level}>"
