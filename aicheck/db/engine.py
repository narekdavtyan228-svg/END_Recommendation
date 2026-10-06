"""Database access: one engine, explicit transactions, no ORM."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Connection, Engine, create_engine, text


def to_sqlalchemy_url(url: str) -> str:
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


class Database:
    def __init__(self, url: str | None = None, engine: Engine | None = None) -> None:
        if engine is None and url is None:
            raise ValueError("url or engine is required")
        self._engine = engine or create_engine(
            to_sqlalchemy_url(url or ""), pool_pre_ping=True, pool_size=10, max_overflow=10
        )
        self._shared: Connection | None = None

    @property
    def engine(self) -> Engine:
        return self._engine

    def bind(self, connection: Connection | None) -> None:
        """Test hook: run every transaction inside one outer transaction (rolled back)."""
        self._shared = connection

    @contextmanager
    def tx(self) -> Iterator[Connection]:
        if self._shared is not None:
            with self._shared.begin_nested():
                yield self._shared
        else:
            with self._engine.begin() as conn:
                yield conn

    def ping(self) -> bool:
        try:
            with self.tx() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - readiness probe must never raise
            return False
        return True

    def dispose(self) -> None:
        self._engine.dispose()
