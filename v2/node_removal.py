"""Compatibility facade for v2.nodes.removal."""
from .nodes.removal import (
    RemovalError,
    delete_remote_objects,
    inspect_remote_state,
    preview,
    remove,
)

__all__ = [
    "RemovalError","preview","remove","delete_remote_objects",
    "inspect_remote_state",
]
