"""Persisted TLS status and periodic read-only certificate checks."""
from __future__ import annotations

import sqlite3
import threading
import time

from ... import agent_transport, storage

LOCK = threading.RLock()
_STARTED = False


def update_status(
    node_id: str, fingerprint: str, expires: int, changed: bool
) -> None:
    now = int(time.time())
    with storage.transaction() as db:
        db.execute(
            """INSERT INTO node_tls_sync(
                 node_id,fingerprint,expires_at,last_checked,last_applied,last_error
               ) VALUES(?,?,?,?,?,'')
               ON CONFLICT(node_id) DO UPDATE SET
                 fingerprint=excluded.fingerprint,
                 expires_at=excluded.expires_at,
                 last_checked=excluded.last_checked,
                 last_applied=CASE WHEN ? THEN excluded.last_applied
                                   ELSE node_tls_sync.last_applied END,
                 last_error=''""",
            (
                node_id,
                fingerprint,
                expires,
                now,
                now if changed else 0,
                int(changed),
            ),
        )
        storage.event(
            db,
            "tls.check",
            node_id,
            "Node-only TLS: reloaded"
            if changed
            else "Node-only TLS verified",
        )


def queue_initial_check(node_id: str) -> bool:
    try:
        node = storage.get_node(node_id)
        if node["status"] != "ready":
            return False
        job = storage.get_install_job(node_id)
        if not job.get("remote_uuid") or not job.get("profile_uuid"):
            return False
        with storage.connect() as db:
            checked = db.execute(
                """SELECT last_checked,last_error
                   FROM node_tls_sync WHERE node_id=?""",
                (node_id,),
            ).fetchone()
            if checked and (
                checked["last_checked"] or checked["last_error"]
            ):
                return False
            prior = db.execute(
                """SELECT id FROM manager_agent_jobs
                   WHERE node_id=? AND action='cert.status' LIMIT 1""",
                (node_id,),
            ).fetchone()
            if prior:
                return False
        agent_transport.enqueue(node_id, "cert.status", ttl=240)
        return True
    except (
        agent_transport.AgentError,
        LookupError,
        sqlite3.OperationalError,
    ):
        return False


def status() -> dict:
    agents = {item["id"]: item for item in agent_transport.nodes_status()}
    with storage.connect() as db:
        rows = db.execute(
            """SELECT n.id,n.code,n.domain,n.status,t.fingerprint,t.expires_at,
                      t.last_checked,t.last_applied,t.last_error,
                      (SELECT COUNT(*) FROM manager_agent_jobs j
                       WHERE j.node_id=n.id AND j.action='cert.status'
                         AND j.status IN ('queued','leased')) AS pending
               FROM nodes n
               LEFT JOIN node_tls_sync t ON n.id=t.node_id
               ORDER BY n.code"""
        ).fetchall()
    return {
        "mode": "node_local_paths",
        "panel_mount_required": False,
        "check_interval_hours": 6,
        "nodes": [
            {
                "id": row["id"],
                "code": row["code"],
                "domain": row["domain"],
                "status": row["status"],
                "expires_at": row["expires_at"] or 0,
                "last_checked": row["last_checked"] or 0,
                "last_applied": row["last_applied"] or 0,
                "last_error": row["last_error"] or "",
                "auto_sync": bool(
                    agents.get(row["id"], {}).get("online")
                ),
                "agent_installed": bool(
                    agents.get(row["id"], {}).get("installed")
                ),
                "checked": bool(row["fingerprint"]),
                "checking": bool(row["pending"]),
            }
            for row in rows
        ],
    }


def background_cycle() -> None:
    for item in status()["nodes"]:
        if item["status"] != "ready" or not item["auto_sync"]:
            continue
        try:
            job = storage.get_install_job(item["id"])
            if not job.get("remote_uuid") or not job.get("profile_uuid"):
                continue
            agent_transport.enqueue(
                item["id"], "cert.status", ttl=240
            )
        except (agent_transport.AgentError, LookupError):
            pass


def start_background() -> None:
    global _STARTED
    with LOCK:
        if _STARTED:
            return
        _STARTED = True

    def worker():
        time.sleep(120)
        while True:
            try:
                background_cycle()
            except Exception:
                pass
            time.sleep(6 * 3600)

    threading.Thread(
        target=worker, name="agent-certbot-sync", daemon=True
    ).start()
