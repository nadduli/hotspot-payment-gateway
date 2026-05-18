import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.tenant.models.tenant import Tenant


class RouterStatus(StrEnum):
    PENDING_SCRIPT = "pending_script"
    ONLINE = "online"
    OFFLINE = "offline"


class Router(Base):
    """A MikroTik device tunneled into the VPS over WireGuard.

    Technical fields (`wireguard_pubkey`, `tunnel_ip`, `api_password_enc`) are
    populated by the router-side registration script callback — operators
    never type them. `api_password_enc` stores AES-256-GCM ciphertext.
    """

    __tablename__ = "routers"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(100))
    registration_token_hash: Mapped[str] = mapped_column(String(128))
    wireguard_pubkey: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # INET on Postgres; plain VARCHAR for cross-DB compat with the SQLite tests.
    tunnel_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    api_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    router_model: Mapped[str | None] = mapped_column(String(50), nullable=True)
    routeros_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    hotspot_server_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[RouterStatus] = mapped_column(
        SAEnum(
            RouterStatus,
            native_enum=False,
            length=20,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        default=RouterStatus.PENDING_SCRIPT,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="routers")

    __table_args__ = (Index("ix_routers_tenant_status", "tenant_id", "status"),)
