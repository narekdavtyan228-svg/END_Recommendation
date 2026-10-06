"""Process entry point: `uvicorn --factory aicheck.api.server:build`."""

from fastapi import FastAPI

from aicheck.api.app import create_app
from aicheck.config import load_settings, validate_outbound
from aicheck.db.engine import Database
from aicheck.logging import configure
from aicheck.runtime import Runtime


def build() -> FastAPI:
    """Read the configuration (the service does not start without it) and build the app."""
    settings = load_settings()
    configure(settings.log_level)
    validate_outbound(settings)
    return create_app(Runtime(settings=settings, db=Database(settings.database_url)))
