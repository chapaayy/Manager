"""Safe, resumable lifecycle of Manager-owned Remnawave nodes.

No hoster VPS deletion, no SSH for deletion. All destructive operations require
a typed node code and a clean dependency graph. Agent self-removal is
acknowledged as *scheduled*, never falsely claimed verified.
"""
import re
import time

from . import agent_transport, remnawave, storage, vps_install
from .template_engine import Endpoint


class LifecycleError(ValueError):
    pass


def initialize():
    with storage.connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS node_lifecycle(
          node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
          archived INTEGER NOT NULL DEFAULT 0,
          phase TEXT NOT NULL DEFAULT '',
          job_id TEXT NOT NULL DEFAULT '',
          delete_profile INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL DEFAULT 0
        );
        """)


def _row(node_id):
    with storage.connect() as db:
        row=db.execute("SELECT * FROM node_lifecycle WHERE node_id=?",(node_id,)).fetchone()
    return dict(row) if row else {"archived":0,"phase":"","job_id":"","delete_profile":1}


def _set(node_id,**changes):
    valid={"archived","phase","job_id","delete_profile"}
    if not changes or not set(changes)<=valid:
        raise LifecycleError("Неверное состояние жизненного цикла")
    with storage.transaction() as db:
        db.execute("INSERT OR IGNORE INTO node_lifecycle(node_id,updated_at) VALUES(?,?)",
                   (node_id,int(time.time())))
        db.execute("UPDATE node_lifecycle SET "+",".join(k+"=?" for k in changes)+
                   ",updated_at=? WHERE node_id=?",
                   (*changes.values(),int(time.time()),node_id))


def _dependencies(node_id):
    with storage.connect() as db:
        results={}
        for table,column in (("bridges","entry_id"),("bridge_exits","exit_id"),
                             ("plans","exit_id")):
            results[table]=db.execute(
                "SELECT COUNT(*) FROM "+table+" WHERE "+column+"=?",(node_id,)).fetchone()[0]
        # The selected node may be a bridge entry, exit, or a planned exit.
    return results


def preview(node_id):
    node=storage.get_node(node_id)
    row=_row(node_id)
    try:job=storage.get_install_job(node_id)
    except LookupError:job=None
    agent=next((a for a in agent_transport.nodes_status() if a["id"]==node_id),{})
    deps=_dependencies(node_id)
    return {"id":node_id,"code":node["code"],"domain":node["domain"],
            "status":node["status"],"archived":bool(row["archived"]),
            "phase":row["phase"],"job_id":row["job_id"],
            "dependencies":deps,"blocked":bool(any(deps.values())),
            "agent_online":bool(agent.get("online")),
            "agent_version":agent.get("version",""),
            "remote_registered":bool(job and job.get("remote_uuid")),
            "profile_created":bool(job and job.get("profile_uuid")),
            "delete_profile":bool(row["delete_profile"]),
            "warnings":["Удаление VPS у хостера не выполняется.",
                        "Удаление в Remnawave прервёт работающие VPN-подключения.",
                        "Удаление из менеджера оставит саму VPS нетронутой."]}


def detach_dependencies(node_id,typed_code):
    """Explicit local topology cleanup ONLY, never edits a deployed Xray config."""
    node=storage.get_node(node_id)
    if typed_code!=node["code"]:
        raise LifecycleError("Для подтверждения введи точный код ноды: "+node["code"])
    if _row(node_id)["phase"]:
        raise LifecycleError("Нельзя менять топологию после начала полного удаления")
    count=_dependencies(node_id)
    with storage.transaction() as db:
        # Removing a bridge entry also cascades its exits and plans. For an
        # exit, delete only that exit's plans/links in other bridges.
        db.execute("DELETE FROM bridges WHERE entry_id=?",(node_id,))
        db.execute("DELETE FROM plans WHERE exit_id=?",(node_id,))
        db.execute("DELETE FROM bridge_exits WHERE exit_id=?",(node_id,))
        storage.event(db,"node.topology.detach",node_id,
                      "Removed local topology links for "+node["code"])
    return {"detached":True,"dependencies_removed":count,
            "remote_configs_untouched":True}


def _guard(node_id,typed_code):
    node=storage.get_node(node_id)
    if typed_code!=node["code"]:
        raise LifecycleError("Для подтверждения введи точный код ноды: "+node["code"])
    blockers=_dependencies(node_id)
    if any(blockers.values()):
        raise LifecycleError("Нода используется мостом или планами. Сначала удали зависимости.")
    return node


def archive(node_id, archived:bool):
    node=storage.get_node(node_id)
    if _row(node_id)["phase"]:
        raise LifecycleError("Во время удаления архивирование запрещено")
    _set(node_id,archived=int(archived))
    with storage.transaction() as db:
        storage.event(db,"node.archive" if archived else "node.restore",
                      node_id,node["code"])
    return {"archived":archived,"id":node_id}


def _delete_record(node_id,action):
    # Delete dependent agent jobs first (FKs are cascade for installed tables).
    with storage.transaction() as db:
        row=db.execute("SELECT code FROM nodes WHERE id=?",(node_id,)).fetchone()
        if row is None:raise LookupError("Нода не найдена")
        db.execute("DELETE FROM nodes WHERE id=?",(node_id,))
        storage.event(db,action,node_id,row["code"])
    return {"deleted":True,"id":node_id,"server_deleted":False}


def forget(node_id,code):
    _guard(node_id,code)
    phase=_row(node_id)["phase"]
    if phase and phase!="finalize_ack":
        raise LifecycleError("Удаление VPS ещё не завершено; нельзя забыть запись")
    return _delete_record(node_id,"node.forget" if not phase else "node.full.finished")


def abandon_interrupted(node_id,code,acknowledge_unverified:bool):
    """Forget an interrupted full cleanup without claiming remote deletion.

    Require explicit typed code and long loss of agent heartbeat. A leased
    task may be executing on the VPS, so never abandon while one is leased.
    This action only deletes the local record and credentials.
    """
    node=_guard(node_id,code)
    if not acknowledge_unverified:
        raise LifecycleError("Подтверди, что состояние VPS и Remnawave не проверено")
    phase=_row(node_id)["phase"]
    if not phase or phase=="finalize_ack":
        raise LifecycleError("Для этой ноды используй обычное удаление записи")
    now=int(time.time())
    with storage.connect() as db:
        row=db.execute(
            "SELECT last_seen FROM manager_agents WHERE node_id=?",(node_id,)).fetchone()
        active=db.execute("""SELECT COUNT(*) FROM manager_agent_jobs
            WHERE node_id=? AND status='leased'""",(node_id,)).fetchone()[0]
    last_seen=row["last_seen"] if row else 0
    if last_seen and now-last_seen<600:
        raise LifecycleError("После последней связи с агентом должно пройти 10 минут")
    if active:
        raise LifecycleError("Агент мог выполнять удаление: дождись завершения или истечения задания")
    with storage.transaction() as db:
        # This logs explicitly what is known and what is unknown.
        storage.event(db,"node.full.abandoned",node_id,
                      "Operator discarded UNVERIFIED deletion phase "+phase+
                      " for "+node["code"]+"; no remote action performed")
        db.execute("DELETE FROM nodes WHERE id=?",(node_id,))
    return {"deleted":True,"id":node_id,"server_deleted":False,
            "remote_cleanup_verified":False,"abandoned_phase":phase}


def _profile_used_by_other(remote_nodes,remote_uuid,profile_uuid):
    from .node_cert_sync import _attached_profile
    if not isinstance(remote_nodes,list):raise LifecycleError("Список нод Remnawave недоступен")
    found=False
    for item in remote_nodes:
        if not isinstance(item,dict):
            raise LifecycleError("Неверный ответ Remnawave")
        try:
            attached,known=_attached_profile(item)
        except ValueError:
            raise LifecycleError("Remnawave вернула некорректные данные профиля") from None
        if not known:
            raise LifecycleError("Неизвестны привязки других Xray-профилей")
        if item.get("uuid")==remote_uuid:
            found=True
            if attached!=profile_uuid:
                raise LifecycleError("У ноды изменился активный Xray-профиль")
        elif attached==profile_uuid:
            raise LifecycleError("Xray-профиль используется другой нодой")
    return found


def _delete_remnawave(node_id,delete_profile):
    node=storage.get_node(node_id)
    job=storage.get_install_job(node_id)
    remote_uuid=job["remote_uuid"]
    profile_uuid=job["profile_uuid"]
    if not remote_uuid and (not profile_uuid or not delete_profile):
        return {"node_removed":False,"profile_removed":False,
                "profile_retained":bool(profile_uuid)}
    try:
        rows=remnawave.request("GET","/api/nodes").get("response")
        if not isinstance(rows,list):
            raise LifecycleError("Не удалось проверить ноды Remnawave")
        found=bool(remote_uuid and any(
            isinstance(n,dict) and n.get("uuid")==remote_uuid for n in rows))
        # Refuse before deleting anything if the profile has unknown owner
        # or is shared. After deleting the node, verify once more.
        if delete_profile and profile_uuid:
            if found:
                _profile_used_by_other(rows,remote_uuid,profile_uuid)
            else:
                _assert_unshared(rows,profile_uuid)
            profile=remnawave.detailed_profile(profile_uuid)
            expected=vps_install.config_profile_name(Endpoint(
                node["code"],node["domain"],node["country"]))
            if profile.get("name")!=expected:
                raise LifecycleError("Имя профиля изменено, автоматическое удаление запрещено")
        if found:
            remnawave.delete_node(remote_uuid)
        if remote_uuid:
            with storage.transaction() as db:
                db.execute("UPDATE node_installations SET remote_uuid='' WHERE node_id=?",(node_id,))
                storage.event(db,"node.remnawave.delete",node_id,"Unregistered "+node["code"])
        deleted_profile=False
        if delete_profile and profile_uuid:
            _assert_unshared(remnawave.request("GET","/api/nodes").get("response"),profile_uuid)
            remnawave.delete_profile(profile_uuid)
            deleted_profile=True
            with storage.transaction() as db:
                db.execute("UPDATE node_installations SET profile_uuid='' WHERE node_id=?",(node_id,))
                storage.event(db,"node.profile.delete",node_id,"Removed dedicated profile")
        return {"node_removed":found,"profile_removed":deleted_profile,
                "profile_retained":bool(profile_uuid and not deleted_profile)}
    except remnawave.PanelError:
        raise LifecycleError("Remnawave API не подтвердило удаление. Проверь доступ и повтори.") from None


def _assert_unshared(rows,profile_uuid):
    from .node_cert_sync import _attached_profile
    if not isinstance(rows,list):
        raise LifecycleError("Не удалось проверить использование Xray-профиля")
    for item in rows:
        if not isinstance(item,dict):raise LifecycleError("Неправильный ответ Remnawave")
        try:
            attached,known=_attached_profile(item)
        except ValueError:
            raise LifecycleError("Remnawave вернула некорректные данные профиля") from None
        if not known:raise LifecycleError("Привязки профилей неизвестны")
        if attached==profile_uuid:raise LifecycleError("Профиль ещё используется нодой")


def delete_remnawave(node_id,code,delete_profile:bool):
    _guard(node_id,code)
    if _row(node_id)["phase"]:
        raise LifecycleError("Идёт полное удаление, используй продолжение операции")
    return _delete_remnawave(node_id,delete_profile)


def _job(node_id,row):
    if not row.get("job_id"):
        raise LifecycleError("В операции нет задания агента")
    return agent_transport.job_status(node_id,row["job_id"])


def begin_full(node_id,code,delete_profile:bool):
    node=_guard(node_id,code)
    row=_row(node_id)
    if row["phase"]:
        raise LifecycleError("Полное удаление уже начато. Продолжи существующее.")
    state=preview(node_id)
    if not state["agent_online"]:
        raise LifecycleError("Для полной очистки VPS агент должен быть онлайн")
    if not state["agent_version"].startswith("1.1."):
        raise LifecycleError("Нужен Node Manager Agent 1.1 или новее для безопасной очистки VPS")
    if node["status"]!="ready":
        raise LifecycleError("Полное удаление возможно только для установленной ноды")
    with storage.connect() as db:
        pending=db.execute("""SELECT COUNT(*) FROM manager_agent_jobs
            WHERE node_id=? AND status IN ('queued','leased')""",(node_id,)).fetchone()[0]
    if pending:
        raise LifecycleError("На ноде есть незавершённые задания агента. Дождись их завершения.")
    task=agent_transport.enqueue(node_id,"node.cleanup",
        {"domain":node["domain"]},ttl=600,internal=True)
    _set(node_id,phase="preparing",job_id=task["id"],delete_profile=int(delete_profile))
    with storage.transaction() as db:
        storage.event(db,"node.full.start",node_id,node["code"])
    return preview(node_id)


def advance_full(node_id,code):
    node=_guard(node_id,code)
    row=_row(node_id)
    phase=row["phase"]
    if phase=="preparing":
        state=_job(node_id,row)
        if state["status"] not in ("done","failed","expired"):
            return {**preview(node_id),"task_status":state["status"]}
        if state["status"]!="done":
            raise LifecycleError("Очистка VPS не подтверждена агентом: "+
                                 (state.get("error") or state["status"]))
        result=state.get("result") or {}
        if (result.get("cleaned") is not True or
            result.get("node")!=node["domain"] or
            result.get("containers_removed") is not True or
            result.get("agent_remains") is not True):
            raise LifecycleError("Агент не подтвердил полную очистку нужной VPS")
        _set(node_id,phase="prepared",job_id="")
        phase="prepared"
    if phase=="prepared":
        _delete_remnawave(node_id,bool(row["delete_profile"]))
        _set(node_id,phase="panel_done")
        phase="panel_done"
    if phase=="panel_done":
        task=agent_transport.enqueue(node_id,"node.cleanup.finish",{
            "domain":node["domain"]},ttl=300,internal=True)
        _set(node_id,phase="finalizing",job_id=task["id"])
        return {**preview(node_id),"task_status":"queued"}
    if phase=="finalizing":
        result=_job(node_id,_row(node_id))
        if result["status"]=="done" and result["result"].get("scheduled") is True:
            _set(node_id,phase="finalize_ack")
            return {**preview(node_id),"shutdown_scheduled":True,
                    "message":"Удаление агента запланировано, но фактический запуск удаления ещё не подтверждён извне."}
        if result["status"] in ("failed","expired"):
            raise LifecycleError("Агент не подтвердил своё удаление: "+
                                 (result["error"] or result["status"]))
        return {**preview(node_id),"task_status":result["status"]}
    if phase=="finalize_ack":
        return {**preview(node_id),"shutdown_scheduled":True}
    raise LifecycleError("Полное удаление не запущено")
