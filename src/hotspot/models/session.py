import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.hotspot.models.router import Router
    from src.payment.models.transaction import Transaction
    from src.tenant.models.tenant import Tenant


class Session(Base):
    """An active hotspot session.

    One Session per successful Transaction. Expiry is enforced by MikroTik
    (limit-uptime); this row exists so the dashboard can show active sessions
    and the cleanup job can mark expired ones.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    transaction_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("transactions.id"), unique=True)
    router_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("routers.id"))
    mac_address: Mapped[str] = mapped_column(String(17))
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mikrotik_username: Mapped[str] = mapped_column(String(80))
    bytes_used: Mapped[int] = mapped_column(BigInteger, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="sessions")
    transaction: Mapped["Transaction"] = relationship()
    router: Mapped["Router"] = relationship()

    __table_args__ = (
        Index("ix_sessions_tenant_is_active", "tenant_id", "is_active"),
        Index("ix_sessions_expires_active", "expires_at", "is_active"),
    )
