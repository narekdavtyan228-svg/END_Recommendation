"""Programmatic Alembic runner (used by the CLI and by tests)."""

from pathlib import Path

from alembic import command
from alembic.config import Config

from aicheck.db.engine import to_sqlalchemy_url

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(owner_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", to_sqlalchemy_url(owner_url).replace("%", "%%"))
    return cfg


def upgrade(owner_url: str, revision: str = "head") -> None:
    command.upgrade(_config(owner_url), revision)


def downgrade(owner_url: str, revision: str = "base") -> None:
    command.downgrade(_config(owner_url), revision)
