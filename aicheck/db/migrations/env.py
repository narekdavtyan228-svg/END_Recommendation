"""Alembic environment: the URL comes from the Config object set by aicheck.db.migrate."""

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config


def run_migrations_online() -> None:
    engine = create_engine(config.get_main_option("sqlalchemy.url") or "", poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=None, version_table_schema="public"
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
