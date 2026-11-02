"""Legacy Agent-based VPS cleanup state machine.

Public HTTP routes for this flow return 410. The code remains isolated only to
finish/inspect historical states and preserve regression coverage until the
legacy-removal cleanup stage.
"""
from __future__ import annotations

import time

from ... import agent_transport, storage
from .errors import LifecycleError
from . import state
from .service import delete_remote_only


def disable_pending_vps_cleanup() -> None:
    with storage.transaction() as db:
        db.execute(
            """UPDATE manager_agent_jobs
               SET status='failed',
                   error='Legacy VPS cleanup disabled by Manager',
                   updated_at=?
               WHERE action IN ('node.cleanup','node.cleanup.finish')
                 AND status='queued'""",
            (int(time.time()),),
        )


def _job(node_id: str, lifecycle: dict) -> dict:
    if not lifecycle.get("job_id"):
        raise LifecycleError("В операции нет задания агента")
    return agent_transport.job_status(
        node_id, lifecycle["job_id"]
    )


def begin_full(
    node_id: str, code: str, delete_profile: bool
) -> dict:
    node = state.guard(node_id, code)
    lifecycle = state.row(node_id)
    if lifecycle["phase"]:
        raise LifecycleError(
            "Полное удаление уже начато. Продолжи существующее."
        )
    preview = state.preview(node_id)
    if not preview["agent_online"]:
        raise LifecycleError(
            "Для полной очистки VPS агент должен быть онлайн"
        )
    if not preview["agent_version"].startswith("1.1."):
        raise LifecycleError(
            "Нужен Node Manager Agent 1.1 или новее "
            "для безопасной очистки VPS"
        )
    if node["status"] != "ready":
        raise LifecycleError(
            "Полное удаление возможно только для установленной ноды"
        )
    with storage.connect() as db:
        pending = db.execute(
            """SELECT COUNT(*) FROM manager_agent_jobs
               WHERE node_id=? AND status IN ('queued','leased')""",
            (node_id,),
        ).fetchone()[0]
    if pending:
        raise LifecycleError(
            "На ноде есть незавершённые задания агента. "
            "Дождись их завершения."
        )

    task = agent_transport.enqueue(
        node_id,
        "node.cleanup",
        {"domain": node["domain"]},
        ttl=600,
        internal=True,
    )
    state.set_state(
        node_id,
        phase="preparing",
        job_id=task["id"],
        delete_profile=int(delete_profile),
    )
    with storage.transaction() as db:
        storage.event(
            db, "node.full.start", node_id, node["code"]
        )
    return state.preview(node_id)


def advance_full(node_id: str, code: str) -> dict:
    node = state.guard(node_id, code)
    lifecycle = state.row(node_id)
    phase = lifecycle["phase"]

    if phase == "preparing":
        task = _job(node_id, lifecycle)
        if task["status"] not in ("done", "failed", "expired"):
            return {
                **state.preview(node_id),
                "task_status": task["status"],
            }
        if task["status"] != "done":
            raise LifecycleError(
                "Очистка VPS не подтверждена агентом: "
                + (task.get("error") or task["status"])
            )
        result = task.get("result") or {}
        if (
            result.get("cleaned") is not True
            or result.get("node") != node["domain"]
            or result.get("containers_removed") is not True
            or result.get("agent_remains") is not True
        ):
            raise LifecycleError(
                "Агент не подтвердил полную очистку нужной VPS"
            )
        state.set_state(
            node_id, phase="prepared", job_id=""
        )
        phase = "prepared"

    if phase == "prepared":
        delete_remote_only(
            node_id, bool(lifecycle["delete_profile"])
        )
        state.set_state(node_id, phase="panel_done")
        phase = "panel_done"

    if phase == "panel_done":
        task = agent_transport.enqueue(
            node_id,
            "node.cleanup.finish",
            {"domain": node["domain"]},
            ttl=300,
            internal=True,
        )
        state.set_state(
            node_id, phase="finalizing", job_id=task["id"]
        )
        return {
            **state.preview(node_id),
            "task_status": "queued",
        }

    if phase == "finalizing":
        task = _job(node_id, state.row(node_id))
        if (
            task["status"] == "done"
            and task["result"].get("scheduled") is True
        ):
            state.set_state(node_id, phase="finalize_ack")
            return {
                **state.preview(node_id),
                "shutdown_scheduled": True,
                "message": (
                    "Удаление агента запланировано, но фактический "
                    "запуск удаления ещё не подтверждён извне."
                ),
            }
        if task["status"] in ("failed", "expired"):
            raise LifecycleError(
                "Агент не подтвердил своё удаление: "
                + (task["error"] or task["status"])
            )
        return {
            **state.preview(node_id),
            "task_status": task["status"],
        }

    if phase == "finalize_ack":
        return {
            **state.preview(node_id),
            "shutdown_scheduled": True,
        }
    raise LifecycleError("Полное удаление не запущено")
