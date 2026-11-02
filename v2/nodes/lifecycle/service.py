"""Active node lifecycle operations that may call Remnawave API."""
from __future__ import annotations

from ... import remnawave, storage
from ..removal.errors import RemovalError
from ..removal.remote import delete_remote_objects
from .errors import LifecycleError
from . import state


def delete_remote_only(
    node_id: str, delete_profile: bool
) -> dict:
    node = storage.get_node(node_id)
    job = storage.get_install_job(node_id)
    try:
        return delete_remote_objects(
            node_id,
            node,
            job,
            delete_profile=delete_profile,
            allow_shared_profile=False,
        )
    except RemovalError as exc:
        raise LifecycleError(str(exc)) from None
    except remnawave.PanelError:
        raise LifecycleError(
            "Remnawave API не подтвердило удаление. "
            "Проверь доступ и повтори."
        ) from None


def delete_remnawave(
    node_id: str, code: str, delete_profile: bool
) -> dict:
    state.guard(node_id, code)
    if state.row(node_id)["phase"]:
        raise LifecycleError(
            "Идёт полное удаление, используй продолжение операции"
        )
    return delete_remote_only(node_id, delete_profile)
