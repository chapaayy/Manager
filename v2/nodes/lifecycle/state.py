"""Local lifecycle state and non-remote node record operations."""
from __future__ import annotations

import time

from ... import agent_transport, storage
from .errors import LifecycleError


def initialize() -> None:
    with storage.connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS node_lifecycle(
              node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
              archived INTEGER NOT NULL DEFAULT 0,
              phase TEXT NOT NULL DEFAULT '',
              job_id TEXT NOT NULL DEFAULT '',
              delete_profile INTEGER NOT NULL DEFAULT 1,
              updated_at INTEGER NOT NULL DEFAULT 0
            );
            """
        )


def row(node_id: str) -> dict:
    with storage.connect() as db:
        item = db.execute(
            "SELECT * FROM node_lifecycle WHERE node_id=?",
            (node_id,),
        ).fetchone()
    return (
        dict(item)
        if item
        else {
            "archived": 0,
            "phase": "",
            "job_id": "",
            "delete_profile": 1,
        }
    )


def set_state(node_id: str, **changes) -> None:
    valid = {"archived", "phase", "job_id", "delete_profile"}
    if not changes or not set(changes) <= valid:
        raise LifecycleError(
            "Неверное состояние жизненного цикла"
        )
    with storage.transaction() as db:
        db.execute(
            """INSERT OR IGNORE INTO node_lifecycle(node_id,updated_at)
               VALUES(?,?)""",
            (node_id, int(time.time())),
        )
        db.execute(
            "UPDATE node_lifecycle SET "
            + ",".join(key + "=?" for key in changes)
            + ",updated_at=? WHERE node_id=?",
            (*changes.values(), int(time.time()), node_id),
        )


def dependencies(node_id: str) -> dict:
    with storage.connect() as db:
        results = {}
        for table, column in (
            ("bridges", "entry_id"),
            ("bridge_exits", "exit_id"),
            ("plans", "exit_id"),
        ):
            results[table] = db.execute(
                "SELECT COUNT(*) FROM "
                + table
                + " WHERE "
                + column
                + "=?",
                (node_id,),
            ).fetchone()[0]
    return results


def preview(node_id: str) -> dict:
    node = storage.get_node(node_id)
    lifecycle = row(node_id)
    try:
        job = storage.get_install_job(node_id)
    except LookupError:
        job = None
    agent = next(
        (
            item
            for item in agent_transport.nodes_status()
            if item["id"] == node_id
        ),
        {},
    )
    deps = dependencies(node_id)
    return {
        "id": node_id,
        "code": node["code"],
        "domain": node["domain"],
        "status": node["status"],
        "archived": bool(lifecycle["archived"]),
        "phase": lifecycle["phase"],
        "job_id": lifecycle["job_id"],
        "dependencies": deps,
        "blocked": bool(any(deps.values())),
        "agent_online": bool(agent.get("online")),
        "agent_version": agent.get("version", ""),
        "remote_registered": bool(job and job.get("remote_uuid")),
        "profile_created": bool(job and job.get("profile_uuid")),
        "delete_profile": bool(lifecycle["delete_profile"]),
        "warnings": [
            "Удаление VPS у хостера не выполняется.",
            "Удаление в Remnawave прервёт работающие VPN-подключения.",
            "Удаление из менеджера оставит саму VPS нетронутой.",
        ],
    }


def detach_dependencies(node_id: str, typed_code: str) -> dict:
    node = storage.get_node(node_id)
    if typed_code != node["code"]:
        raise LifecycleError(
            "Для подтверждения введи точный код ноды: "
            + node["code"]
        )
    if row(node_id)["phase"]:
        raise LifecycleError(
            "Нельзя менять топологию после начала полного удаления"
        )
    count = dependencies(node_id)
    with storage.transaction() as db:
        db.execute(
            "DELETE FROM bridges WHERE entry_id=?", (node_id,)
        )
        db.execute(
            "DELETE FROM plans WHERE exit_id=?", (node_id,)
        )
        db.execute(
            "DELETE FROM bridge_exits WHERE exit_id=?", (node_id,)
        )
        storage.event(
            db,
            "node.topology.detach",
            node_id,
            "Removed local topology links for " + node["code"],
        )
    return {
        "detached": True,
        "dependencies_removed": count,
        "remote_configs_untouched": True,
    }


def guard(node_id: str, typed_code: str) -> dict:
    node = storage.get_node(node_id)
    if typed_code != node["code"]:
        raise LifecycleError(
            "Для подтверждения введи точный код ноды: "
            + node["code"]
        )
    blockers = dependencies(node_id)
    if any(blockers.values()):
        raise LifecycleError(
            "Нода используется мостом или планами. "
            "Сначала удали зависимости."
        )
    return node


def archive(node_id: str, archived: bool) -> dict:
    node = storage.get_node(node_id)
    if row(node_id)["phase"]:
        raise LifecycleError(
            "Во время удаления архивирование запрещено"
        )
    set_state(node_id, archived=int(archived))
    with storage.transaction() as db:
        storage.event(
            db,
            "node.archive" if archived else "node.restore",
            node_id,
            node["code"],
        )
    return {"archived": archived, "id": node_id}


def delete_record(node_id: str, action: str) -> dict:
    with storage.transaction() as db:
        item = db.execute(
            "SELECT code FROM nodes WHERE id=?", (node_id,)
        ).fetchone()
        if item is None:
            raise LookupError("Нода не найдена")
        db.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        storage.event(db, action, node_id, item["code"])
    return {
        "deleted": True,
        "id": node_id,
        "server_deleted": False,
    }


def forget(node_id: str, code: str) -> dict:
    guard(node_id, code)
    phase = row(node_id)["phase"]
    if phase and phase != "finalize_ack":
        raise LifecycleError(
            "Удаление VPS ещё не завершено; нельзя забыть запись"
        )
    return delete_record(
        node_id,
        "node.forget" if not phase else "node.full.finished",
    )


def abandon_interrupted(
    node_id: str,
    code: str,
    acknowledge_unverified: bool,
) -> dict:
    node = guard(node_id, code)
    if not acknowledge_unverified:
        raise LifecycleError(
            "Подтверди, что состояние VPS и Remnawave не проверено"
        )
    phase = row(node_id)["phase"]
    if not phase or phase == "finalize_ack":
        raise LifecycleError(
            "Для этой ноды используй обычное удаление записи"
        )

    now = int(time.time())
    with storage.connect() as db:
        agent = db.execute(
            "SELECT last_seen FROM manager_agents WHERE node_id=?",
            (node_id,),
        ).fetchone()
        active = db.execute(
            """SELECT COUNT(*) FROM manager_agent_jobs
               WHERE node_id=? AND status='leased' AND updated_at>?""",
            (node_id, now - 600),
        ).fetchone()[0]

    last_seen = agent["last_seen"] if agent else 0
    if last_seen and now - last_seen < 600:
        raise LifecycleError(
            "После последней связи с агентом должно пройти 10 минут"
        )
    if active:
        raise LifecycleError(
            "Агент мог выполнять удаление: "
            "дождись завершения или истечения задания"
        )

    with storage.transaction() as db:
        storage.event(
            db,
            "node.full.abandoned",
            node_id,
            "Operator discarded UNVERIFIED deletion phase "
            + phase
            + " for "
            + node["code"]
            + "; no remote action performed",
        )
        db.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    return {
        "deleted": True,
        "id": node_id,
        "server_deleted": False,
        "remote_cleanup_verified": False,
        "abandoned_phase": phase,
    }
