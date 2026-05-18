import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.audit.models import AuditLog
    from src.auth.models.user import User
    from src.hotspot.models.router import Router
    from src.hotspot.models.session import Session
    from src.payment.models.payment_config import PaymentConfig
    from src.payment.models.plan import Plan
    from src.payment.models.transaction import Transaction


class TenantStatus(StrEnum):
    PENDING_VERIFICATION = "pending_verification"
    PENDING_SETUP = "pending_setup"
    ACTIVE = "active"
    SUSPENDED = "suspended"


class Tenant(Base):
    """Top of the data hierarchy. Owns every other row via `tenant_id` FKs.

    Single-tenant deployments use one fixed row (see DEFAULT_TENANT_ID).
    Multi-tenant Phase B adds signup-based provisioning per spec §7.
    """

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    business_name: Mapped[str] = mapped_column(String(150))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    owner_email: Mapped[str] = mapped_column(String(200))
    status: Mapped[TenantStatus] = mapped_column(
        SAEnum(
            TenantStatus,
            native_enum=False,
            length=40,
            # Store the lowercase enum *value*, not the uppercase Python name,
            # so raw SQL reads/writes match the model.
            values_callable=lambda enum: [e.value for e in enum],
        ),
        default=TenantStatus.PENDING_SETUP,
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    setup_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    accent_color: Mapped[str] = mapped_column(String(7), default="#2E75B6")
    logo_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    welcome_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    plans: Mapped[list["Plan"]] = relationship(back_populates="tenant")
    routers: Mapped[list["Router"]] = relationship(back_populates="tenant")
    payment_configs: Mapped[list["PaymentConfig"]] = relationship(back_populates="tenant")
    transactions: Mapped[list["Transaction"]] = relationship(back_populates="tenant")
    sessions: Mapped[list["Session"]] = relationship(back_populates="tenant")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="tenant")
