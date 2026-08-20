"""Time helpers for a database that stores explicit UTC as naive timestamps."""

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)
