"""HTTP translation for common domain/storage failures."""
from __future__ import annotations

import sqlite3

from fastapi import HTTPException

from ..template_engine import TemplateError


def api_failure(exc: Exception):
    if isinstance(exc, sqlite3.IntegrityError):
        raise HTTPException(
            409,
            "Такая запись уже существует или связана с другой. Обнови страницу и проверь карточки.",
        ) from None
    if isinstance(exc, (ValueError, TemplateError)):
        raise HTTPException(422, str(exc)) from None
    if isinstance(exc, LookupError):
        raise HTTPException(404, str(exc)) from None
    raise exc
