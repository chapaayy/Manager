"""Node lifecycle public surface with legacy cleanup isolated."""
from .errors import LifecycleError
from .state import (
    abandon_interrupted,
    archive,
    delete_record as _delete_record,
    dependencies as _dependencies,
    detach_dependencies,
    forget,
    guard as _guard,
    initialize,
    preview,
    row as _row,
    set_state as _set,
)
from .legacy_cleanup import (
    advance_full,
    begin_full,
    disable_pending_vps_cleanup,
)


def delete_remnawave(
    node_id: str, code: str, delete_profile: bool
):
    from .service import delete_remnawave as operation

    return operation(node_id, code, delete_profile)


__all__ = [
    "LifecycleError","initialize","disable_pending_vps_cleanup","preview",
    "detach_dependencies","archive","forget","abandon_interrupted",
    "delete_remnawave","begin_full","advance_full","_row","_set",
    "_dependencies","_guard","_delete_record",
]
