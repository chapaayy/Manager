"""Node inventory persistence."""
from __future__ import annotations

import time
import uuid

from ..core.database import connect, transaction
from ..core.events import record as event

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
        return [dict(row) for row in c.execute("""
            SELECT n.*, COALESCE(l.archived,0) AS archived,
                   COALESCE(l.phase,'') AS lifecycle_phase
            FROM nodes n LEFT JOIN node_lifecycle l ON l.node_id=n.id
            ORDER BY n.role,n.code""").fetchall()]


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
