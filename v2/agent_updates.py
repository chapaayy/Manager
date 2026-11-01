"""Per-node opt-in auto-updates and explicit manual updater; no arbitrary URLs."""
from __future__ import annotations
import time
import threading

from . import agent_release, agent_transport, storage


_SCHEDULE_LOCK=threading.Lock()


class UpdateError(ValueError):
    pass


def current(node_id:str)->dict:
    node=storage.get_node(node_id)
    with storage.connect() as db:
        row=db.execute("""SELECT version,auto_update,last_seen,last_status_json
                       FROM manager_agents WHERE node_id=? AND enabled=1""",(node_id,)).fetchone()
    if row is None:
        raise UpdateError("Агент не зарегистрирован")
    import json
    metrics=json.loads(row["last_status_json"] or "{}")
    arch=metrics.get("architecture")
    rel=agent_release.release()
    current_version=row["version"] or ""
    target=rel["binaries"].get(arch,{})
    modern=agent_release.compare(current_version,"1.3.0")>=0
    upgrade_needed=bool(agent_release.compare(rel["version"],current_version)>0 and
                        (bool(target) or not modern and bool(rel["binaries"])))
    return {"node_id":node_id,"node_code":node["code"],
            "current_version":current_version,"latest_version":rel["version"],
            "architecture":arch or "unknown","auto_update":bool(row["auto_update"]),
            "online":bool(row["last_seen"] and int(time.time())-row["last_seen"]<agent_transport.online_window()),
            "upgrade_needed":upgrade_needed,"supports_self_update":modern,
            "artifact_ready":bool(target) or not modern and bool(rel["binaries"]),
            "one_time_ssh_migration_required":not modern and upgrade_needed}


def _require_upgrade(node_id:str):
    result=current(node_id)
    if not result["online"]:
        raise UpdateError("Агент офлайн: сначала восстанови связь")
    if not result["upgrade_needed"]:
        raise UpdateError("Последняя доступная версия агента уже установлена")
    if not result["artifact_ready"]:
        raise UpdateError("Нет собранного бинарного файла для архитектуры агента")
    return result


def manual(node_id:str,*,confirmed:bool,password:str="")->dict:
    if not confirmed:
        raise UpdateError("Подтверди обновление агента")
    result=_require_upgrade(node_id)
    if not result["supports_self_update"]:
        if not password:
            raise UpdateError("Для первого обновления старого агента нужен SSH-пароль root")
        from . import agent_bootstrap
        outcome=agent_bootstrap.upgrade_existing(node_id,password,True)
        return {**outcome,"mode":"one-time-ssh","latest_version":result["latest_version"]}
    with storage.connect() as db:
        recent=db.execute("""SELECT 1 FROM manager_agent_jobs
                             WHERE node_id=? AND action='agent.update' AND created_at>?
                             LIMIT 1""",(node_id,int(time.time())-120)).fetchone()
    if recent:
        raise UpdateError("Обновление агента уже запущено; дождись подтверждения новой версии")
    return {**agent_transport.enqueue(node_id,"agent.update",_payload(result),ttl=900),
            "mode":"agent","latest_version":result["latest_version"]}


def set_auto(node_id:str,enabled:bool)->dict:
    storage.get_node(node_id)
    with storage.transaction() as db:
        row=db.execute("SELECT enabled FROM manager_agents WHERE node_id=?",(node_id,)).fetchone()
        if row is None or not row["enabled"]:
            raise UpdateError("Агент не зарегистрирован")
        db.execute("UPDATE manager_agents SET auto_update=?,last_update_check=0 WHERE node_id=?",
                   (int(enabled),node_id))
        if not enabled:
            db.execute("""UPDATE manager_agent_jobs
                       SET status='failed',error='Automatic updates disabled',updated_at=?
                       WHERE node_id=? AND action='agent.update' AND status='queued'
                         AND payload_json LIKE '%"automatic":true%'""",
                       (int(time.time()),node_id))
        storage.event(db,"agent.autoupdate",node_id,"Enabled" if enabled else "Disabled")
    return current(node_id)


def _payload(info:dict)->dict:
    arch=info["architecture"]
    binary=agent_release.release()["binaries"].get(arch)
    if binary is None:
        raise UpdateError("Agent artifact missing")
    return dict(binary)


def auto_schedule(node_id:str,version:str,metrics:dict)->bool:
    with _SCHEDULE_LOCK:
        return _auto_schedule_locked(node_id,version,metrics)


def _auto_schedule_locked(node_id:str,version:str,metrics:dict)->bool:
    # Heartbeats from old agents or unsupported architectures are read-only.
    if agent_release.compare(version,"1.3.0")<0:
        return False
    arch=metrics.get("architecture")
    if arch not in ("amd64","arm64"):
        return False
    now=int(time.time())
    with storage.connect() as db:
        row=db.execute("SELECT auto_update,last_update_check FROM manager_agents WHERE node_id=? AND enabled=1",
                       (node_id,)).fetchone()
    if not row or not row["auto_update"] or now-row["last_update_check"]<3600:
        return False
    release=agent_release.release()
    if arch not in release["binaries"] or agent_release.compare(release["version"],version)<=0:
        return False
    with storage.connect() as db:
        recent=db.execute("""SELECT 1 FROM manager_agent_jobs
                             WHERE action='agent.update' AND created_at>?
                             LIMIT 1""",(now-120,)).fetchone()
        if recent:
            return False
        pending=db.execute("""SELECT 1 FROM manager_agent_jobs
                              WHERE node_id=? AND action='agent.update' AND status IN ('queued','leased')
                              LIMIT 1""",(node_id,)).fetchone()
    if pending:
        return False
    try:
        agent_transport.enqueue(node_id,"agent.update",{**release["binaries"][arch],"automatic":True},ttl=900,internal=True)
    except (agent_transport.AgentError,LookupError):
        return False
    with storage.transaction() as db:
        db.execute("UPDATE manager_agents SET last_update_check=? WHERE node_id=?",(now,node_id))
        storage.event(db,"agent.update.queued",node_id,"Auto-update scheduled")
    return True
