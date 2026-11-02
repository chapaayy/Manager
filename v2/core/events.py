"""Audit event persistence."""
from __future__ import annotations

import time


def record(connection, action: str, target: str, message: str) -> None:
    connection.execute(
        "INSERT INTO events(time,action,target,message) VALUES(?,?,?,?)",
        (int(time.time()), action, target, message[:500]),
    )
