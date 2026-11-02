"""XPPN Manager v2 application bootstrap.

HTTP routes live in v2.api, process-wide infrastructure in v2.core, and domain
logic remains outside the FastAPI application layer.
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .api.router import router
from .core.http import protective_headers
from .core.lifecycle import startup
from .core.auth import _password_ok  # compatibility: old tests/imports
from .core.config import admin_username as _username  # compatibility alias

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="XPPN 2.0 — isolated preview",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
app.on_event("startup")(startup)
app.middleware("http")(protective_headers)
app.include_router(router)
