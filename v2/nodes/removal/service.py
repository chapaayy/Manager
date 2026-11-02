"""Operator-facing node removal orchestration."""
from __future__ import annotations

import re
import threading

from ... import remnawave, storage
from ..lifecycle import state as lifecycle_state
from .errors import RemovalError
from .remote import delete_remote_objects, inspect_remote_state

_LOCK = threading.RLock()


def _install(node_id: str):
    try:
        return storage.get_install_job(node_id)
    except LookupError:
        return None


def preview(node_id: str) -> dict:
    node = storage.get_node(node_id)
    base = lifecycle_state.preview(node_id)
    job = _install(node_id)
    result = {
        **base,
        "remnawave_available": True,
        "remnawave_error": "",
        "remote_uuid": job["remote_uuid"] if job else "",
        "profile_uuid": job["profile_uuid"] if job else "",
        "remote_present": False,
        "profile_present": False,
        "profile_name": "",
        "profile_owned": False,
        "shared_nodes": [],
    }
    try:
        result.update(inspect_remote_state(node, job))
    except (remnawave.PanelError, RemovalError):
        result["remnawave_available"] = False
        result["remnawave_error"] = (
            "Не удалось безопасно проверить ноды и профили Remnawave. "
            "Доступно только удаление из менеджера."
        )
    return result


def _check_legacy_tasks(node_id: str) -> None:
    with storage.connect() as db:
        pending = db.execute(
            """SELECT COUNT(*) FROM manager_agent_jobs
               WHERE node_id=?
                 AND action IN ('node.cleanup','node.cleanup.finish')
                 AND status IN ('queued','leased')""",
            (node_id,),
        ).fetchone()[0]
    if pending:
        raise RemovalError(
            "Есть незавершённая задача старой очистки VPS. "
            "Нельзя гарантировать, что она не выполняется."
        )


def remove(
    node_id: str,
    code: str,
    *,
    delete_remote: bool,
    delete_profile: bool,
    shared_confirmation: str = "",
    expected_shared_ids: list[str] | None = None,
):
    with _LOCK:
        node = lifecycle_state.guard(node_id, code)
        _check_legacy_tasks(node_id)
        if delete_profile and not delete_remote:
            raise RemovalError(
                "Нельзя удалять профиль без операции с Remnawave"
            )

        remote_result = {
            "node_removed": False,
            "profile_removed": False,
            "profile_retained": False,
        }
        job = _install(node_id)
        if delete_remote and job:
            try:
                remote_result = delete_remote_objects(
                    node_id,
                    node,
                    job,
                    delete_profile=delete_profile,
                    allow_shared_profile=True,
                    shared_confirmation=shared_confirmation,
                    expected_shared_ids=expected_shared_ids,
                )
            except remnawave.PanelError as exc:
                match = re.search(
                    r"(?<!\d)HTTP\s+([45]\d\d)\b", str(exc)
                )
                suffix = (
                    " (HTTP " + match.group(1) + ")"
                    if match
                    else ""
                )
                raise RemovalError(
                    "Remnawave API не подтвердила операцию" + suffix
                ) from None
        elif not delete_remote:
            remote_result["profile_retained"] = bool(
                job and job["profile_uuid"]
            )

        with storage.transaction() as db:
            storage.event(
                db,
                "node.manager.removal",
                node_id,
                "Remote API requested: "
                + str(bool(delete_remote))
                + "; profile deleted: "
                + str(bool(delete_profile))
                + "; VPS left untouched",
            )

        result = lifecycle_state.delete_record(
            node_id, "node.manager.removed"
        )
        return {
            **result,
            **remote_result,
            "vps_touched": False,
        }
