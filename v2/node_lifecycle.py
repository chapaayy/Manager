"""Compatibility facade for v2.nodes.lifecycle."""
from .nodes.lifecycle import (
    LifecycleError,
    _delete_record,
    _dependencies,
    _guard,
    _row,
    _set,
    abandon_interrupted,
    advance_full,
    archive,
    begin_full,
    delete_remnawave,
    detach_dependencies,
    disable_pending_vps_cleanup,
    forget,
    initialize,
    preview,
)

__all__ = [
    "LifecycleError","initialize","disable_pending_vps_cleanup","preview",
    "detach_dependencies","archive","forget","abandon_interrupted",
    "delete_remnawave","begin_full","advance_full","_row","_set",
    "_dependencies","_guard","_delete_record",
]
