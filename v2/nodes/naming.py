"""Stable naming rules shared by node installation and ownership checks."""
from __future__ import annotations

from ..xray import Endpoint


def config_profile_name(source: Endpoint, mode: str = "direct") -> str:
    return (
        f"XPPN {source.code} {source.country} BRIDGE VLESS TLS"
        if mode == "bridge"
        else f"XPPN {source.code} {source.country} VLESS TLS"
    )
