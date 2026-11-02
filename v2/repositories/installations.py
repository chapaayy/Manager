"""Node installation job persistence."""
from __future__ import annotations

import json
import time

from ..core.database import connect, decrypt, encrypt, transaction
from ..core.events import record as event

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
    result=dict(row)
    result.pop("preset_snapshot_enc",None)
    result.pop("ssh_password_enc",None)
    return result


def save_install_preset(node_id: str, preset_id: str, snapshot: dict) -> None:
    # Freeze exact selected configuration revision before the background worker
    # starts; edits to the library cannot silently change an in-flight install.
    raw=json.dumps(snapshot,ensure_ascii=False,separators=(",",":"))
    with transaction() as c:
        changed=c.execute(
            "UPDATE node_installations SET preset_id=?,preset_snapshot_enc=? WHERE node_id=? AND stage='queued'",
            (preset_id,encrypt(raw),node_id))
        if changed.rowcount!=1:
            raise ValueError("Пресет установки можно зафиксировать только до старта")


def get_install_preset(node_id: str) -> dict | None:
    with connect() as c:
        row=c.execute(
            "SELECT preset_snapshot_enc FROM node_installations WHERE node_id=?",
            (node_id,)).fetchone()
    if not row or not row["preset_snapshot_enc"]:
        return None
    return json.loads(decrypt(row["preset_snapshot_enc"]))


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
