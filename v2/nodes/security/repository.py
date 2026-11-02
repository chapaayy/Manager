"""Persistence for desired/applied node security revisions."""
from __future__ import annotations

import json
import time

from ... import storage
from .model import default_config, normalize


def initialize() -> None:
    with storage.connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS node_security_settings(
              node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
              config_json TEXT NOT NULL,
              revision INTEGER NOT NULL DEFAULT 1,
              applied_revision INTEGER NOT NULL DEFAULT 0,
              last_job_id TEXT NOT NULL DEFAULT '',
              updated_at INTEGER NOT NULL DEFAULT 0,
              applied_at INTEGER NOT NULL DEFAULT 0
            );
            """
        )


def get(node_id: str) -> dict:
    storage.get_node(node_id)
    initialize()
    with storage.connect() as db:
        row = db.execute(
            """SELECT config_json,revision,applied_revision,last_job_id,
                      updated_at,applied_at
               FROM node_security_settings WHERE node_id=?""",
            (node_id,),
        ).fetchone()
    if not row:
        return {
            "node_id": node_id,
            "config": default_config(),
            "revision": 0,
            "applied_revision": 0,
            "last_job_id": "",
            "updated_at": 0,
            "applied_at": 0,
            "changed_since_apply": True,
        }

    try:
        config = normalize(json.loads(row["config_json"]))
    except (ValueError, json.JSONDecodeError):
        config = default_config()

    return {
        "node_id": node_id,
        "config": config,
        "revision": int(row["revision"]),
        "applied_revision": int(row["applied_revision"]),
        "last_job_id": row["last_job_id"],
        "updated_at": int(row["updated_at"]),
        "applied_at": int(row["applied_at"]),
        "changed_since_apply": (
            int(row["revision"]) != int(row["applied_revision"])
        ),
    }


def save(
    node_id: str, config: dict, expected_revision: int
) -> dict:
    storage.get_node(node_id)
    normalized = normalize(config)
    if (
        not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise ValueError("Некорректная ревизия настроек")

    initialize()
    now = int(time.time())
    encoded = json.dumps(
        normalized, separators=(",", ":"), sort_keys=True
    )
    with storage.transaction() as db:
        row = db.execute(
            """SELECT revision FROM node_security_settings
               WHERE node_id=?""",
            (node_id,),
        ).fetchone()
        if row is None:
            if expected_revision != 0:
                raise ValueError(
                    "Настройки уже изменились. Обнови страницу."
                )
            revision = 1
            db.execute(
                """INSERT INTO node_security_settings
                   (node_id,config_json,revision,updated_at)
                   VALUES(?,?,?,?)""",
                (node_id, encoded, revision, now),
            )
        else:
            if int(row["revision"]) != expected_revision:
                raise ValueError(
                    "Настройки уже изменились. Обнови страницу."
                )
            revision = expected_revision + 1
            db.execute(
                """UPDATE node_security_settings
                   SET config_json=?,revision=?,updated_at=?
                   WHERE node_id=?""",
                (encoded, revision, now, node_id),
            )
        storage.event(
            db,
            "node.security.settings",
            node_id,
            f"Security settings revision {revision}",
        )
    return get(node_id)


def set_last_job(node_id: str, job_id: str, revision: int) -> None:
    with storage.transaction() as db:
        db.execute(
            """UPDATE node_security_settings SET last_job_id=?
               WHERE node_id=?""",
            (job_id, node_id),
        )
        storage.event(
            db,
            "node.security.apply",
            node_id,
            f"Queued security revision {revision}",
        )


def mark_applied(node_id: str, result: dict) -> None:
    revision = result.get("revision")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
    ):
        return
    now = int(time.time())
    initialize()
    with storage.transaction() as db:
        row = db.execute(
            """SELECT revision FROM node_security_settings
               WHERE node_id=?""",
            (node_id,),
        ).fetchone()
        if not row:
            return
        db.execute(
            """UPDATE node_security_settings
               SET applied_revision=?,applied_at=?
               WHERE node_id=?""",
            (revision, now, node_id),
        )
        storage.event(
            db,
            "node.security.applied",
            node_id,
            f"Applied security revision {revision}",
        )
