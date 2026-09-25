"""IOC (Indicator of Compromise) SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, DateTime, JSON, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class IOC(Base, TimestampMixin, RetentionMixin):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type = Column(String, nullable=False)               # ip / domain / hash_md5 / hash_sha256 / cve / url / email
    value = Column(String, nullable=False)
    severity = Column(String, nullable=True)                # critical / high / medium / low
    status = Column(String, nullable=True, default="active")  # active / expired / false_positive
    source = Column(String, nullable=True)
    context = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True, default=list)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    meta_data = Column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return f"<IOC id={self.id} type={self.ioc_type} value={self.value!r}>"
