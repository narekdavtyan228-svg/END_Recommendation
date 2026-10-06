"""Single source of the current time (UTC). Tests replace `now`."""

from collections.abc import Callable
from datetime import UTC, datetime

_source: Callable[[], datetime] = lambda: datetime.now(UTC)  # noqa: E731


def now() -> datetime:
    return _source()


def set_source(source: Callable[[], datetime] | None) -> None:
    """Test hook: pass None to restore the real clock."""
    global _source
    _source = source or (lambda: datetime.now(UTC))
