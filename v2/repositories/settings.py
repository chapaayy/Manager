"""Manager-wide persisted settings."""
from __future__ import annotations

import time

from ..core.database import connect, transaction
from ..core.events import record as event

def monitoring_interval() -> float:
    with connect() as c:
        row=c.execute("SELECT monitor_interval FROM panel WHERE id=1").fetchone()
    value=float(row["monitor_interval"] if row else 5)
    return value if value in (1,2,5,10,15,30,60) else 5


def set_monitoring_interval(value: float) -> dict:
    value=float(value)
    if value not in (1,2,5,10,15,30,60):
        raise ValueError("Недопустимый интервал мониторинга")
    with transaction() as c:
        c.execute("UPDATE panel SET monitor_interval=?,updated_at=? WHERE id=1",
                  (value,int(time.time())))
        event(c,"settings.monitoring","panel",f"Monitoring interval {value:g}s")
    return {"monitor_interval":value}
