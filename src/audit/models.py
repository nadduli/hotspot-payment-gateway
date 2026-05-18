import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.tenant.models.tenant import Tenant


class AuditLog(Base):
    """Append-only record of every event that touches money or router state.

    Used for forensics when a customer disputes a charge. Distinct from the
    structlog access log: this is durable, queryable, tenant-scoped, and
    survives log rotation.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    # e.g. PAYMENT_INITIATED, WEBHOOK_RECEIVED, MIKROTIK_USER_CREATED
    event_type: Mapped[str] = mapped_column(String(50))
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[uuid.UUID] = mapped_column()
    # operator email | "system" | "webhook" | "router-callback"
    actor: Mapped[str] = mapped_column(String(100))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="audit_logs")

    __table_args__ = (Index("ix_audit_logs_tenant_created", "tenant_id", "created_at"),)
