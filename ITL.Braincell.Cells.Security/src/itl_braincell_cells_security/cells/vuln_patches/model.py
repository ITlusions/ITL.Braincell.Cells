"""VulnPatch SQLAlchemy model"""
import uuid
from sqlalchemy import Column, String, Text
from sqlalchemy.dialects.postgresql import UUID

from itl_braincell_sdk.core.models import Base, TimestampMixin, RetentionMixin


class VulnPatch(Base, TimestampMixin, RetentionMixin):
    """A known-vulnerable code snippet paired with its patched equivalent."""

    __tablename__ = "vuln_patches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    vulnerable_code = Column(Text, nullable=True)
    patched_code = Column(Text, nullable=True)
    patch_explanation = Column(Text, nullable=True)
    language = Column(String, nullable=True)
    category = Column(String, nullable=True)                # sql_injection / xss / ssrf / ...
    severity = Column(String, nullable=True)                # critical / high / medium / low

    def __repr__(self) -> str:
        return f"<VulnPatch id={self.id} title={self.title!r} category={self.category}>"
