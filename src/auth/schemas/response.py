from typing import Literal

from pydantic import BaseModel


class SuccessResponse[DataT](BaseModel):
    """Standardized success response schema."""

    status: Literal["success"] = "success"
    message: str
    data: DataT | None = None


class ErrorResponse(BaseModel):
    """Standardized error response schema."""

    status: Literal["error"] = "error"
    message: str
