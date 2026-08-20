"""Time helpers for a database that stores explicit UTC as naive timestamps."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
