"""Process-wide HTTP middleware."""
from __future__ import annotations


async def protective_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response
