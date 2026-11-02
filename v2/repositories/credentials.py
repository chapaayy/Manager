"""Encrypted node SSH bootstrap/recovery credentials."""
from __future__ import annotations

import time

from ..core.database import connect, decrypt, encrypt, transaction
from ..core.events import record as event

def save_node_ssh_password(node_id: str,password: str) -> None:
    if not isinstance(password,str) or not 1<=len(password)<=512 or "\x00" in password:
        raise ValueError("Некорректный SSH-пароль")
    with transaction() as c:
        if c.execute("UPDATE node_installations SET ssh_password_enc=?,updated_at=? WHERE node_id=?",
                     (encrypt(password),int(time.time()),node_id)).rowcount!=1:
            raise LookupError("Установка ноды не найдена")
        event(c,"node.ssh_credentials",node_id,"SSH password updated")


def node_ssh_credentials(node_id: str, *, include_secret: bool=False) -> dict:
    with connect() as c:
        row=c.execute("SELECT ip,port,ssh_fingerprint,ssh_password_enc FROM node_installations WHERE node_id=?",
                      (node_id,)).fetchone()
    if not row: raise LookupError("Установка ноды не найдена")
    result={"ip":row["ip"],"port":row["port"],"fingerprint":row["ssh_fingerprint"],
            "has_password":bool(row["ssh_password_enc"])}
    if include_secret and row["ssh_password_enc"]:
        result["password"]=decrypt(row["ssh_password_enc"])
    return result


def clear_node_ssh_password(node_id: str) -> dict:
    with transaction() as c:
        if c.execute("UPDATE node_installations SET ssh_password_enc='',updated_at=? WHERE node_id=?",
                     (int(time.time()),node_id)).rowcount!=1:
            raise LookupError("Установка ноды не найдена")
        event(c,"node.ssh_credentials",node_id,"SSH password cleared")
