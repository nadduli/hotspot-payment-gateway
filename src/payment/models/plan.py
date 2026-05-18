import uuid
from datetime import datetime, time
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Time, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models import Base, uuid7_pk

if TYPE_CHECKING:
    from src.tenant.models.tenant import Tenant


class Plan(Base):
    """A purchasable hotspot package. Mapped to MikroTik user-profile + limit-uptime."""

    __tablename__ = "plans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7_pk)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    # UGX is the unit; Relworx minimum is 500.
    price_ugx: Mapped[int] = mapped_column(Integer)
    duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_down_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_up_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data_limit_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data_limit_down_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data_limit_up_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    separate_limits: Mapped[bool] = mapped_column(Boolean, default=False)
    simultaneous_devices: Mapped[int] = mapped_column(Integer, default=1)
    # Array of weekday ints (0=Mon..6=Sun). Empty list = available every day.
    available_days: Mapped[list[int]] = mapped_column(JSON, default=list)
    available_from: Mapped[time | None] = mapped_column(Time, nullable=True)
    available_until: Mapped[time | None] = mapped_column(Time, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    display_color: Mapped[str | None] = mapped_column(String(7), nullable=True)
    is_featured: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tenant: Mapped["Tenant"] = relationship(back_populates="plans")
