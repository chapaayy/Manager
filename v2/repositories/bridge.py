"""Legacy bridge persistence.

Bridge HTTP behavior remains disabled; this repository preserves existing data
and compatibility until the dedicated legacy cleanup stage.
"""
from __future__ import annotations

import json
import time
import uuid

from ..core.database import connect, decrypt, encrypt, transaction
from ..core.events import record as event
from .nodes import get_node

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
    from ..template_engine import validate_rendered
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
