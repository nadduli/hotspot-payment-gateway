import uuid

from sqlalchemy.orm import DeclarativeBase
from uuid_utils import uuid7


class Base(DeclarativeBase):
    pass


def uuid7_pk() -> uuid.UUID:
    """Time-ordered UUID7 returned as a stdlib uuid.UUID.

    `uuid_utils.UUID` is not a subclass of `uuid.UUID` and doesn't compare equal
    to one with identical bytes — asyncpg + SQLAlchemy's `Uuid` type round-trip
    through the stdlib class, so leaving the in-memory PK as a `uuid_utils.UUID`
    breaks `session.refresh()`. Coerce at generation time and the rest of the
    codebase only ever sees stdlib UUIDs.
    """
    return uuid.UUID(bytes=uuid7().bytes)
