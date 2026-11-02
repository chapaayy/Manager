"""Compatibility facade for the unified v2.nodes.tls subsystem."""
from .nodes.tls.errors import CertificateSyncError
from .nodes.tls.profile import (
    api_error as _api_error,
    attached_profile as _attached_profile,
    owned_profile as _profile,
)
from .nodes.tls.service import (
    apply_agent_export,
    apply_agent_status,
    migrate_to_local_paths,
    sync,
)
from .nodes.tls.state import (
    LOCK,
    background_cycle,
    queue_initial_check,
    start_background,
    status,
)

__all__ = [
    "CertificateSyncError","LOCK","_api_error","_attached_profile","_profile",
    "apply_agent_export","apply_agent_status","migrate_to_local_paths","sync",
    "background_cycle","queue_initial_check","start_background","status",
]
