"""Generic response envelopes shared across endpoints."""

from typing import Literal

from pydantic import BaseModel


class SuccessResponse[DataT](BaseModel):
    """Generic success envelope; `data` carries the typed payload."""

    status: Literal["success"] = "success"
    message: str
    data: DataT | None = None


class ErrorResponse(BaseModel):
    """Generic error envelope with a human-readable message."""

    status: Literal["error"] = "error"
    message: str
