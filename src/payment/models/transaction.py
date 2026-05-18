import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.hotspot.models.router import Router
    from src.payment.models.plan import Plan
    from src.tenant.models.tenant import Tenant


class TransactionStatus(StrEnum):
    """Lifecycle states per spec §8.4.

    PENDING       -> Relworx called, awaiting webhook
    SUCCESS       -> webhook confirmed; provisioning not yet attempted
    PROVISIONING  -> attempting to create the MikroTik hotspot user
    COMPLETED     -> hotspot user exists; customer can log in (terminal happy)
    FAILED        -> webhook returned failure (insufficient balance, declined)
    EXPIRED       -> PENDING for >10min with no webhook
    """

    PENDING = "pending"
    SUCCESS = "success"
    PROVISIONING = "provisioning"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class PaymentProvider(StrEnum):
    MTN_UGANDA = "mtn_uganda"
    AIRTEL_UGANDA = "airtel_uganda"


class Transaction(Base):
    """Permanent record of every payment attempt. Never deleted.

    `id` is the customer_reference sent to Relworx — webhooks correlate back
    via this UUID.
    """

    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("plans.id"))
    router_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("routers.id"))
    phone_number: Mapped[str] = mapped_column(String(15))
    amount_ugx: Mapped[int] = mapped_column(Integer)
    status: Mapped[TransactionStatus] = mapped_column(
        SAEnum(
            TransactionStatus,
            native_enum=False,
            length=20,
            values_callable=lambda enum: [e.value for e in enum],
        ),
        default=TransactionStatus.PENDING,
    )
    relworx_internal_ref: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    provider: Mapped[PaymentProvider] = mapped_column(
        SAEnum(
            PaymentProvider,
            native_enum=False,
            length=20,
            values_callable=lambda enum: [e.value for e in enum],
        )
    )
    relworx_charge_ugx: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    mikrotik_username: Mapped[str | None] = mapped_column(String(80), nullable=True)
    mikrotik_password: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # First-time webhook receipt; guards against duplicate processing.
    webhook_received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    provisioning_attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="transactions")
    plan: Mapped["Plan"] = relationship()
    router: Mapped["Router"] = relationship()

    __table_args__ = (
        # Recent transactions for the dashboard — hot read.
        Index("ix_transactions_tenant_created", "tenant_id", "created_at"),
        # Filter by status in the transactions screen.
        Index(
            "ix_transactions_tenant_status_created",
            "tenant_id",
            "status",
            "created_at",
        ),
    )
