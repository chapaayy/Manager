"""Shared API-only helpers for node operator credentials."""
from __future__ import annotations

from .. import storage


def node_password(node_id: str, supplied: str = "") -> str:
    if supplied:
        return supplied
    try:
        return storage.node_ssh_credentials(node_id, include_secret=True).get("password", "")
    except LookupError:
        return ""
