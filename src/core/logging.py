"""Structured logging via structlog. Console renderer in dev, JSON in production."""

import logging
import sys
from typing import Any

import structlog

from src.core.config import get_settings


def configure_logging() -> None:
    """Configure structlog. Idempotent — safe to re-call from tests."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    """Return a structlog logger. Prefer `log = get_logger(__name__)` at module top."""
    return structlog.get_logger(name)
