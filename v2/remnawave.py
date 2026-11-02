"""Compatibility facade for the Remnawave integration.

New implementation lives in v2.integrations.remnawave. Keeping this module
preserves the existing import surface while Stage 2 moves behavior into
resource-focused modules.
"""
from .integrations.remnawave.errors import PanelError
from .integrations.remnawave import client as _client
from .integrations.remnawave import profiles as _profiles
from .integrations.remnawave import nodes as _nodes
from .integrations.remnawave import service as _service

PinnedHTTPS = _client.PinnedHTTPS
validate_url = _client.validate_url
guard_node_only_tls_paths = _client.guard_node_only_tls_paths
_panel_error_details = _client._panel_error_details

# Intentionally a mutable module global. Existing tests and diagnostics patch
# remnawave.request; all facade operations resolve it at call time.
request = _client.request


def list_profiles() -> list[dict]:
    return _profiles.list_profiles(request)


def validate_profile_selection(profile: str, inbounds: list[str]) -> None:
    return _profiles.validate_profile_selection(list_profiles, profile, inbounds)


def panel_status() -> dict:
    return _service.panel_status(list_profiles, request)


def node_secret() -> str:
    return _nodes.node_secret(request)


def create_profile(name: str, xray_config: dict) -> dict:
    return _profiles.create_profile(request, list_profiles, name, xray_config)


def register_node(
    name: str,
    address: str,
    country: str,
    profile_uuid: str,
    inbound_uuids: list[str],
) -> str:
    return _nodes.register_node(
        request, name, address, country, profile_uuid, inbound_uuids
    )


def node_health(node_uuid: str) -> dict:
    return _nodes.node_health(request, node_uuid)


def detailed_profile(uuid: str) -> dict:
    return _profiles.detailed_profile(request, uuid)


def replace_profile_config(uuid: str, config: dict):
    return _profiles.replace_profile_config(request, uuid, config)


def restart_node(uuid: str):
    return _nodes.restart_node(request, uuid)


def delete_node(uuid: str):
    return _nodes.delete_node(request, uuid)


def delete_profile(uuid: str):
    return _profiles.delete_profile(request, uuid)
