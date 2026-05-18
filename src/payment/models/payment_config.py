import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.tenant.models.tenant import Tenant


class PaymentConfig(Base):
    """Per-tenant Relworx credentials.

    `api_key_enc` and `webhook_secret_enc` hold AES-256-GCM ciphertext; the
    encryption helper that wraps/unwraps lives in `src/core/encryption.py`
    (added in Slice 2 with the Relworx integration).
    """

    __tablename__ = "payment_configs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(100))
    account_no: Mapped[str] = mapped_column(String(80))
    api_key_enc: Mapped[str] = mapped_column(Text)
    webhook_secret_enc: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_result: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="payment_configs")
