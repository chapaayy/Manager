"""Compatibility facade for the disabled Bridge service."""
from .bridge.service import as_endpoint, plan_public, prepare_bridge_exit

__all__ = ["as_endpoint", "plan_public", "prepare_bridge_exit"]
