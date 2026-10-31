"""Single-panel persistent store for XPPN Manager 2.

No projects table, no project_id, no legacy multitenancy. The old v1 DB
is never opened for writes. Xray JSON and network credentials are encrypted
in SQLite with XPPN_DATA_KEY.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from cryptography.fernet import Fernet


def db_path() -> str:
    return os.environ.get("XPPN_V2_DB", "/data/xppn-v2.db")


def cipher() -> Fernet:
    key = os.environ.get("XPPN_DATA_KEY")
    if not key:
        raise RuntimeError("XPPN_DATA_KEY is required; do not generate a new key on each reboot")
    return Fernet(key.encode())


def encrypt(value: str) -> str:
    return cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    return cipher().decrypt(value.encode("ascii")).decode("utf-8")


@contextlib.contextmanager
def connect():
    connection = sqlite3.connect(db_path(), timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    try:
        yield connection
    finally:
        connection.close()


@contextlib.contextmanager
def transaction():
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
        except Exception:
            c.execute("ROLLBACK")
            raise
        else:
            c.execute("COMMIT")


def init_db():
    cipher()  # Check encryption settings before touching a database.
    path = db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS panel (
            id INTEGER PRIMARY KEY CHECK(id=1),
            url TEXT NOT NULL DEFAULT '',
            outbound_ip TEXT NOT NULL DEFAULT '',
            token_enc TEXT NOT NULL DEFAULT '',
            caddy_api_key_enc TEXT NOT NULL DEFAULT '',
            config_profile_uuid TEXT NOT NULL DEFAULT '',
            inbound_uuids_json TEXT NOT NULL DEFAULT '[]',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            domain TEXT NOT NULL UNIQUE,
            country TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('regular','entry','exit')),
            status TEXT NOT NULL DEFAULT 'planned',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bridges (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            entry_id TEXT NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE RESTRICT,
            revision INTEGER NOT NULL DEFAULT 0,
            snapshot_enc TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bridge_exits (
            bridge_id TEXT NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
            exit_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
            inbound_port INTEGER NOT NULL CHECK(inbound_port BETWEEN 443 AND 8999),
            uuid_enc TEXT NOT NULL,
            PRIMARY KEY(bridge_id,exit_id),
            UNIQUE(bridge_id,inbound_port)
        );
        CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            bridge_id TEXT NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
            exit_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
            source_revision INTEGER NOT NULL,
            proposal_enc TEXT NOT NULL,
            outgoing_uuid_enc TEXT NOT NULL,
            inbound_port INTEGER NOT NULL,
            diff_redacted TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('draft','approved','deployed','rejected')),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_plans_bridge ON plans(bridge_id,created_at DESC);
        CREATE TABLE IF NOT EXISTS node_installations (
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            ssh_fingerprint TEXT NOT NULL,
            stage TEXT NOT NULL CHECK(stage IN
               ('queued','installing','registered','ready','failed','interrupted')),
            note TEXT NOT NULL DEFAULT '',
            remote_uuid TEXT NOT NULL DEFAULT '',
            profile_uuid TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_installed_vps_ip ON node_installations(ip);
        CREATE TABLE IF NOT EXISTS certificate_settings (
            id INTEGER PRIMARY KEY CHECK(id=1),
            enabled INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO certificate_settings(id) VALUES(1);
        CREATE TABLE IF NOT EXISTS node_certificates (
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            sync_key_enc TEXT NOT NULL DEFAULT '',
            profile_mode TEXT NOT NULL DEFAULT 'inline',
            last_applied INTEGER NOT NULL DEFAULT 0,
            applied_fingerprint TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL DEFAULT 0,
            fingerprint TEXT NOT NULL DEFAULT '',
            last_synced INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS cert_profile_backups (
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            config_enc TEXT NOT NULL,
            profile_uuid TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS starter_seeds (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS library_configs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('xray','nginx','nginx_compose','node_compose')),
            content_enc TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS presets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS preset_items (
            preset_id TEXT NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
            config_id TEXT NOT NULL REFERENCES library_configs(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            PRIMARY KEY(preset_id,kind)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time INTEGER NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            message TEXT NOT NULL
        );
        INSERT OR IGNORE INTO panel(id) VALUES(1);
        """)
        # Add new credentials without resetting an existing v2 database.
        columns = {r["name"] for r in c.execute("PRAGMA table_info(panel)").fetchall()}
        if "caddy_api_key_enc" not in columns:
            c.execute("ALTER TABLE panel ADD COLUMN caddy_api_key_enc TEXT NOT NULL DEFAULT ''")
        cert_columns = {r["name"] for r in c.execute("PRAGMA table_info(node_certificates)")}
        if "profile_mode" not in cert_columns:
            c.execute("ALTER TABLE node_certificates ADD COLUMN profile_mode TEXT NOT NULL DEFAULT 'inline'")
        if "last_applied" not in cert_columns:
            c.execute("ALTER TABLE node_certificates ADD COLUMN last_applied INTEGER NOT NULL DEFAULT 0")
        if "applied_fingerprint" not in cert_columns:
            c.execute("ALTER TABLE node_certificates ADD COLUMN applied_fingerprint TEXT NOT NULL DEFAULT ''")



def event(c, action: str, target: str, message: str):
    c.execute("INSERT INTO events(time,action,target,message) VALUES(?,?,?,?)",
              (int(time.time()), action, target, message[:500]))


def get_panel() -> dict:
    with connect() as c:
        r = c.execute("SELECT * FROM panel WHERE id=1").fetchone()
        if not r:
            raise RuntimeError("Storage not initialized")
    return {
        "url": r["url"], "outbound_ip": r["outbound_ip"],
        "has_token": bool(r["token_enc"]),
        "has_caddy_api_key": bool(r["caddy_api_key_enc"]),
        "config_profile_uuid": r["config_profile_uuid"],
        "inbound_uuids": json.loads(r["inbound_uuids_json"]),
        "updated_at": r["updated_at"],
    }


def set_panel(*, url: str, outbound_ip: str = "", token: str | None = None,
              caddy_api_key: str | None = None):
    with transaction() as c:
        row = c.execute("SELECT url,token_enc,caddy_api_key_enc FROM panel WHERE id=1").fetchone()
        previous = row["token_enc"]
        current_url = row["url"]
        current_caddy_key = row["caddy_api_key_enc"] if current_url == url else ""
        if caddy_api_key is not None:
            current_caddy_key = encrypt(caddy_api_key) if caddy_api_key else ""
        if current_url and current_url != url and token is None:
            raise ValueError("При смене домена панели повторно введи API-токен")
        if token is not None:
            previous = encrypt(token) if token else ""
        c.execute("""UPDATE panel SET url=?, outbound_ip=?, token_enc=?,caddy_api_key_enc=?,
                  config_profile_uuid=CASE WHEN url<>? THEN '' ELSE config_profile_uuid END,
                  inbound_uuids_json=CASE WHEN url<>? THEN '[]' ELSE inbound_uuids_json END,
                  updated_at=? WHERE id=1""",
                  (url, outbound_ip, previous, current_caddy_key, url, url, int(time.time())))
        event(c, "panel.update", "panel", "Updated single panel connection")
    return get_panel()


def get_panel_token() -> str:
    with connect() as c:
        row = c.execute("SELECT token_enc FROM panel WHERE id=1").fetchone()
    return decrypt(row["token_enc"]) if row and row["token_enc"] else ""


def get_caddy_api_key() -> str:
    with connect() as c:
        row = c.execute("SELECT caddy_api_key_enc FROM panel WHERE id=1").fetchone()
    return decrypt(row["caddy_api_key_enc"]) if row and row["caddy_api_key_enc"] else ""


def set_panel_profile(profile_uuid: str, inbound_uuids: list[str]):
    with transaction() as c:
        c.execute("""UPDATE panel SET config_profile_uuid=?,inbound_uuids_json=?,updated_at=? WHERE id=1""",
                  (profile_uuid, json.dumps(inbound_uuids), int(time.time())))
        event(c, "panel.profile", profile_uuid, "Selected inbound IDs")
    return get_panel()


def create_node(*, code: str, name: str, domain: str, country: str, role: str) -> dict:
    ident = str(uuid.uuid4())
    if role not in ("regular", "entry", "exit"):
        raise ValueError("Некорректная роль сервера")
    with transaction() as c:
        existing = c.execute("SELECT code,domain,status FROM nodes WHERE code=? OR domain=? LIMIT 1",
                             (code,domain)).fetchone()
        if existing:
            raise ValueError(
                f"Сервер {existing['code']} с доменом {existing['domain']} уже добавлен "
                "в менеджер. Открой его карточку и продолжи установку, "
                "вместо создания второй записи."
            )
        c.execute("""INSERT INTO nodes(id,code,name,domain,country,role,created_at)
                     VALUES(?,?,?,?,?,?,?)""",
                  (ident, code, name, domain, country, role, int(time.time())))
        event(c, "node.create", ident, f"Created {role} node {code}")
    return get_node(ident)


def get_node(node_id: str) -> dict:
    with connect() as c:
        r = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not r:
        raise LookupError("Нода не найдена")
    return dict(r)


def list_nodes() -> list[dict]:
    with connect() as c:
        return [dict(row) for row in c.execute("SELECT * FROM nodes ORDER BY role,code").fetchall()]


def _delete_unused_draft_in_tx(c, node_id: str) -> dict:
    row = c.execute("SELECT id,code,name,domain,role,status FROM nodes WHERE id=?",
                    (node_id,)).fetchone()
    if row is None:
        raise LookupError("Черновик не найден")
    if row["status"] != "planned":
        raise ValueError("Удалять можно только черновики, установка которых ещё не начиналась")
    dependencies = (
        ("node_installations","node_id"), ("bridges","entry_id"),
        ("bridge_exits","exit_id"), ("plans","exit_id"),
    )
    for table, column in dependencies:
        if c.execute(f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1",(node_id,)).fetchone():
            raise ValueError("Черновик уже используется или связан с установкой/мостом. Удаление запрещено")
    c.execute("DELETE FROM nodes WHERE id=?",(node_id,))
    event(c,"node.draft.delete",node_id,
          f"Removed unused draft {row['code']} ({row['domain']})")
    return {"deleted": True,"id":row["id"],"code":row["code"]}


def delete_unused_draft(node_id: str) -> dict:
    """Never delete installed/connected nodes or any record with dependencies."""
    with transaction() as c:
        return _delete_unused_draft_in_tx(c,node_id)


def remove_one_time_test_rus10() -> bool:
    """User-authorized one-time cleanup of the known RUS10 test card.

    A recorded marker prevents a newly created RUS10 draft being deleted on
    a later restart. No actual remote VPS, Remnawave node or config is touched.
    """
    marker = "cleanup:test-rus10-gowayot:2026-10"
    with transaction() as c:
        if c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(marker,)).fetchone():
            return False
        row = c.execute("""SELECT id FROM nodes WHERE
             code='RUS10' AND name='RUS10' AND domain='rus10.gowayot.com'
             AND role='regular' AND status='planned' LIMIT 1""").fetchone()
        removed=False
        if row:
            try:
                _delete_unused_draft_in_tx(c,row["id"])
                removed=True
            except ValueError:
                # If the test card has any dependencies, leave it untouched.
                pass
        c.execute("INSERT INTO starter_seeds(name,applied_at) VALUES(?,?)",
                  (marker,int(time.time())))
        return removed


def create_install_job(node_id: str, ip: str, port: int, ssh_fingerprint: str) -> dict:
    with transaction() as c:
        now = int(time.time())
        record = c.execute("SELECT status FROM nodes WHERE id=?",(node_id,)).fetchone()
        if record is None:
            raise LookupError("Нода не найдена")
        if record["status"] != "planned":
            raise ValueError("Этот сервер уже устанавливался. Повторная установка поверх него запрещена.")
        if c.execute("SELECT 1 FROM node_installations WHERE node_id=?",(node_id,)).fetchone():
            raise ValueError("Для этой ноды уже существует задача установки.")
        c.execute(
            """INSERT INTO node_installations
                (node_id,ip,port,ssh_fingerprint,stage,note,created_at,updated_at)
               VALUES(?,?,?,?,'queued','Ожидание установки',?,?)""",
            (node_id,ip,port,ssh_fingerprint,now,now))
        c.execute("UPDATE nodes SET status='queued' WHERE id=?",(node_id,))
        event(c,"node.install.queued",node_id,"Approved clean VPS setup queued")
    return get_install_job(node_id)


def queue_resume_install(node_id: str) -> dict:
    """Atomically claim a failed/interrupted installation for registration-only recovery."""
    with transaction() as c:
        row = c.execute(
            """SELECT i.stage,i.remote_uuid,n.status FROM node_installations i
               JOIN nodes n ON n.id=i.node_id WHERE i.node_id=?""", (node_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Установка не найдена")
        if row["stage"] not in ("failed", "interrupted") or row["status"] != row["stage"]:
            raise ValueError("Продолжение доступно только после ошибки или прерывания установки")
        if row["remote_uuid"]:
            raise ValueError("Нода уже зарегистрирована в Remnawave. Повторное создание запрещено.")
        now = int(time.time())
        c.execute("""UPDATE node_installations SET stage='queued',
                     note='Возобновление: проверяем установленную VPS', updated_at=?
                     WHERE node_id=?""", (now,node_id))
        c.execute("UPDATE nodes SET status='queued' WHERE id=?", (node_id,))
        event(c,"node.install.resume",node_id,"Registration-only recovery requested")
    return get_install_job(node_id)


def delete_failed_install(node_id: str) -> dict:
    """Forget a terminal, unregistered attempt locally. Never touch the remote VPS."""
    with transaction() as c:
        row = c.execute(
            """SELECT n.code,n.status,i.stage,i.remote_uuid
               FROM nodes n JOIN node_installations i ON i.node_id=n.id
               WHERE n.id=?""", (node_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Завершённая неудачная установка не найдена")
        if (row["status"] not in ("failed", "interrupted")
                or row["stage"] != row["status"]):
            raise ValueError("Удалять можно только завершённые неудачные установки, не активные и не рабочие ноды")
        if row["remote_uuid"]:
            raise ValueError("Нода уже зарегистрирована в Remnawave. Удаление записи запрещено.")
        for table,column in (("bridges","entry_id"),("bridge_exits","exit_id"),("plans","exit_id")):
            if c.execute(f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1",(node_id,)).fetchone():
                raise ValueError("Нода используется мостом или планом. Удаление запрещено.")
        c.execute("DELETE FROM node_installations WHERE node_id=?",(node_id,))
        c.execute("DELETE FROM nodes WHERE id=?",(node_id,))
        event(c,"node.install.forget",node_id,"Forgot unsuccessful unregistered "+row["code"])
        return {"deleted":True,"id":node_id,"code":row["code"],"remote_untouched":True}


def set_install_status(node_id: str, stage: str, note: str, *,
                       remote_uuid: str = "", profile_uuid: str = ""):
    if stage not in {"queued","installing","registered","ready","failed","interrupted"}:
        raise ValueError("Неверное состояние установки")
    with transaction() as c:
        changed = c.execute(
            """UPDATE node_installations
               SET stage=?, note=?, updated_at=?,
                   remote_uuid=CASE WHEN ?<>'' THEN ? ELSE remote_uuid END,
                   profile_uuid=CASE WHEN ?<>'' THEN ? ELSE profile_uuid END
               WHERE node_id=?""",
            (stage,note[:350],int(time.time()),remote_uuid,remote_uuid,
             profile_uuid,profile_uuid,node_id))
        if changed.rowcount!=1:
            raise LookupError("Установка ноды не найдена")
        c.execute("UPDATE nodes SET status=? WHERE id=?",(stage,node_id))
        event(c,"node.install."+stage,node_id,note[:180])


def get_install_job(node_id: str) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM node_installations WHERE node_id=?",(node_id,)).fetchone()
    if not row:
        raise LookupError("Установка не найдена")
    return dict(row)


def mark_interrupted_jobs():
    """The SSH password is kept only in worker memory; a restart cannot resume."""
    with transaction() as c:
        c.execute("""UPDATE node_installations
                  SET stage='interrupted',
                    note='Менеджер перезапущен во время установки. Проверь VPS вручную перед повтором.',
                    updated_at=?
                  WHERE stage IN ('installing','queued')""",(int(time.time()),))
        c.execute("""UPDATE nodes SET status='interrupted'
                    WHERE id IN (SELECT node_id FROM node_installations WHERE stage='interrupted')""")


def create_bridge(entry_id: str, name: str) -> dict:
    source = get_node(entry_id)
    if source["role"] != "entry":
        raise ValueError("Мост можно создать только для входной ноды")
    ident = str(uuid.uuid4())
    with transaction() as c:
        c.execute("INSERT INTO bridges(id,name,entry_id,created_at) VALUES(?,?,?,?)",
                  (ident, name, entry_id, int(time.time())))
        event(c, "bridge.create", ident, f"Bridge source: {source['code']}")
    return get_bridge(ident)


def get_bridge(bridge_id: str) -> dict:
    with connect() as c:
        r = c.execute("SELECT * FROM bridges WHERE id=?", (bridge_id,)).fetchone()
        if not r:
            raise LookupError("Мост не найден")
        row = dict(r)
        exits = [dict(x) for x in c.execute(
            """SELECT n.id,n.code,n.name,n.domain,n.country,n.status,e.inbound_port
               FROM bridge_exits e JOIN nodes n ON n.id=e.exit_id
               WHERE e.bridge_id=? ORDER BY e.inbound_port""", (bridge_id,)).fetchall()]
        pending = [dict(x) for x in c.execute(
            """SELECT p.id,p.status,p.created_at,n.code AS exit_code,p.inbound_port
               FROM plans p JOIN nodes n ON n.id=p.exit_id
               WHERE p.bridge_id=? AND p.status IN ('draft','approved')
               ORDER BY p.created_at DESC""", (bridge_id,)).fetchall()]
    row["has_snapshot"] = bool(row["snapshot_enc"])
    row.pop("snapshot_enc")
    row["entry"] = get_node(row["entry_id"])
    row["exits"] = exits
    row["plans"] = pending
    return row


def list_bridges() -> list[dict]:
    with connect() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM bridges ORDER BY created_at").fetchall()]
    return [get_bridge(ident) for ident in ids]


def save_snapshot(bridge_id: str, value: dict, *, expected_revision: int):
    """Import the ACTUAL currently deployed Xray JSON without modifying the VPS."""
    from .template_engine import validate_rendered
    validate_rendered(value)
    encrypted = encrypt(json.dumps(value, ensure_ascii=False))
    with transaction() as c:
        row = c.execute("SELECT revision FROM bridges WHERE id=?", (bridge_id,)).fetchone()
        if not row:
            raise LookupError("Мост не найден")
        if row["revision"] != expected_revision:
            raise ValueError("Состояние моста изменилось; загрузи его заново")
        c.execute("UPDATE bridges SET snapshot_enc=?,revision=revision+1 WHERE id=?",
                  (encrypted, bridge_id))
        c.execute("UPDATE plans SET status='rejected' WHERE bridge_id=? AND status IN ('draft','approved')", (bridge_id,))
        event(c, "bridge.snapshot", bridge_id, "Imported read-only Xray snapshot")
    return get_bridge(bridge_id)


def get_snapshot(bridge_id: str) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT snapshot_enc FROM bridges WHERE id=?", (bridge_id,)).fetchone()
    if not r:
        raise LookupError("Мост не найден")
    return json.loads(decrypt(r["snapshot_enc"])) if r["snapshot_enc"] else None


def create_plan(bridge_id: str, exit_id: str, *, content: dict, outgoing_uuid: str,
                inbound_port: int, diff_redacted: str) -> dict:
    """Prepare immutable encrypted preview. Does NOT update live node or active graph."""
    new_id = str(uuid.uuid4())
    with transaction() as c:
        bridge = c.execute("SELECT revision,entry_id FROM bridges WHERE id=?", (bridge_id,)).fetchone()
        if not bridge:
            raise LookupError("Мост не найден")
        if exit_id == bridge["entry_id"]:
            raise ValueError("Нельзя добавить входной сервер как выходной")
        if c.execute("SELECT 1 FROM bridge_exits WHERE bridge_id=? AND exit_id=?",
                     (bridge_id, exit_id)).fetchone():
            raise ValueError("Эта выходная нода уже подключена к мосту")
        if c.execute("""SELECT 1 FROM plans WHERE bridge_id=? AND exit_id=?
                        AND status IN ('draft','approved')""", (bridge_id, exit_id)).fetchone():
            raise ValueError("Для этого выхода уже существует незавершённый план")
        c.execute("""INSERT INTO plans(id,bridge_id,exit_id,source_revision,proposal_enc,
                     outgoing_uuid_enc,inbound_port,diff_redacted,status,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (new_id, bridge_id, exit_id, bridge["revision"],
                   encrypt(json.dumps(content, ensure_ascii=False)), encrypt(outgoing_uuid),
                   inbound_port, diff_redacted, "draft", int(time.time())))
        event(c, "plan.prepare", new_id, "Created encrypted dry-run for bridge exit")
    return get_plan(new_id)


def get_plan(plan_id: str) -> dict:
    with connect() as c:
        row = c.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not row:
        raise LookupError("План не найден")
    return {
        "id": row["id"], "bridge_id": row["bridge_id"], "exit_id": row["exit_id"],
        "source_revision": row["source_revision"], "inbound_port": row["inbound_port"],
        "status": row["status"], "diff": row["diff_redacted"], "created_at": row["created_at"],
        "note": "Черновик. На VPS и Remnawave ничего не изменилось.",
    }


def get_plan_config(plan_id: str) -> dict:
    """INTERNAL ONLY: never expose full UUIDs in JSON API or logs."""
    with connect() as c:
        row = c.execute("SELECT proposal_enc FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not row:
        raise LookupError("План не найден")
    return json.loads(decrypt(row["proposal_enc"]))


def approve_plan(plan_id: str) -> dict:
    """Approval stages a plan; live deployment requires a separately audited adapter."""
    with transaction() as c:
        row = c.execute("SELECT bridge_id,source_revision,status FROM plans WHERE id=?", (plan_id,)).fetchone()
        if not row:
            raise LookupError("План не найден")
        if row["status"] != "draft":
            raise ValueError("Подтвердить можно только черновик")
        current = c.execute("SELECT revision FROM bridges WHERE id=?", (row["bridge_id"],)).fetchone()
        if current["revision"] != row["source_revision"]:
            raise ValueError("Конфигурация уже изменилась; создай новый предпросмотр")
        c.execute("UPDATE plans SET status='approved' WHERE id=?", (plan_id,))
        event(c, "plan.approve", plan_id, "Approved but NOT deployed")
    return get_plan(plan_id)
