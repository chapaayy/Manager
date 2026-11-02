"""Compatibility facade for node-local TLS helpers."""
from .nodes.tls.errors import LocalTLSError
from .nodes.tls.profile import certificate_slot as profile_slot, paths
from .nodes.tls.validation import agent_status
from .nodes.tls.state import update_status
from .nodes.tls.service import migration, report
from .nodes.tls import service as _service

# Existing tests patch node_local_tls.time.sleep. This is the same module object
# used by the new service, so the compatibility patch remains effective.
time = _service.time

__all__ = [
    "LocalTLSError","paths","agent_status","profile_slot","update_status",
    "report","migration","time",
]
