"""Compatibility facade for legacy Bridge persistence.

The implementation is isolated in :mod:`v2.bridge.repository`.
"""
from ..bridge.repository import (
    approve_plan,
    create_bridge,
    create_plan,
    get_bridge,
    get_plan,
    get_plan_config,
    get_snapshot,
    list_bridges,
    save_snapshot,
)

__all__ = [
    "approve_plan",
    "create_bridge",
    "create_plan",
    "get_bridge",
    "get_plan",
    "get_plan_config",
    "get_snapshot",
    "list_bridges",
    "save_snapshot",
]
