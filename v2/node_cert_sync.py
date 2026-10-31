"""Node-local Certbot TLS, fingerprint-only sync via Agent; no PEM crosses Manager."""
import threading
import time


from . import agent_transport, remnawave, storage, vps_install
from .template_engine import Endpoint

LOCK=threading.RLock()
_STARTED=False


class CertificateSyncError(ValueError):
    pass


def _attached_profile(row:dict) -> tuple[str|None,bool]:
    """Return known attached UUID and whether the assignment is represented.

    Explicitly unassigned Remnawave nodes (null) do not share profiles.
    Missing assignment fields are UNKNOWN, not safe proof of isolation.
    """
    profile=row.get("configProfile")
    if isinstance(profile,dict):
        if "activeConfigProfileUuid" in profile:
            value=profile["activeConfigProfileUuid"]
            if value is None or value=="":
                return None,True
            if isinstance(value,str):
                return value,True
            raise CertificateSyncError("Remnawave вернула некорректную привязку профиля")
    if "configProfileUuid" in row:
        value=row["configProfileUuid"]
        if value is None or value=="":
            return None,True
        if isinstance(value,str):
            return value,True
        raise CertificateSyncError("Remnawave вернула некорректный UUID профиля")
    if "activeConfigProfileUuid" in row:
        value=row["activeConfigProfileUuid"]
        if value is None or value=="":
            return None,True
        if isinstance(value,str):
            return value,True
        raise CertificateSyncError("Remnawave вернула некорректный UUID профиля")
    if "configProfile" in row and profile is None:
        return None,True
    return None,False


def _api_error(exc:Exception) -> str:
    """Keep only HTTP code. Remnawave's error body may contain secret PEM."""
    import re
    match=re.search(r"(?<!\d)HTTP\s+([45]\d\d)\b",str(exc))
    return " (HTTP "+match.group(1)+")" if match else ""


def _profile(node,job):
    try:
        rows=remnawave.request("GET","/api/nodes").get("response")
    except remnawave.PanelError as exc:
        raise CertificateSyncError("Не удалось получить список нод через Remnawave API"+
                                   _api_error(exc)) from None
    if not isinstance(rows,list):
        raise CertificateSyncError("Remnawave вернула неправильный формат списка нод")
    own=False
    for n in rows:
        if not isinstance(n,dict):
            raise CertificateSyncError("Некорректный ответ Remnawave о нодах")
        attached,known=_attached_profile(n)
        if not known:
            raise CertificateSyncError("Remnawave не вернула привязки профилей для проверки безопасности")
        if n.get("uuid")==job["remote_uuid"]:
            own=True
            if attached!=job["profile_uuid"]:
                raise CertificateSyncError("У ноды изменился активный Xray-профиль")
        elif attached==job["profile_uuid"]:
            raise CertificateSyncError("Xray-профиль используется другой нодой, изменение запрещено")
        # A *known* empty assignment is safe: it cannot reference this profile.
    if not own:
        raise CertificateSyncError("Нода не найдена в Remnawave API")
    try:
        data=remnawave.detailed_profile(job["profile_uuid"])
    except remnawave.PanelError as exc:
        raise CertificateSyncError("Не удалось прочитать Xray-профиль через API"+
                                   _api_error(exc)) from None
    expected=vps_install.config_profile_name(Endpoint(
        node["code"],node["domain"],node["country"]))
    if data.get("name")!=expected:
        raise CertificateSyncError("Имя Xray-профиля отличается от созданного менеджером")
    return data


def apply_agent_export(node_id:str,data:dict)->dict:
    # This API previously transported private keys to the Panel. Disabled.
    raise CertificateSyncError("Передача приватных ключей отключена: используй cert.status")


def apply_agent_status(node_id:str,data:dict)->dict:
    from . import node_local_tls
    try:
        with LOCK:
            return node_local_tls.report(node_id,data)
    except node_local_tls.LocalTLSError as exc:
        raise CertificateSyncError(str(exc)) from None


def migrate_to_local_paths(node_id:str,code:str,cert_job_id:str,compose_job_id:str):
    from . import node_local_tls
    try:
        with LOCK:
            return node_local_tls.migration(node_id,code,cert_job_id,compose_job_id)
    except node_local_tls.LocalTLSError as exc:
        raise CertificateSyncError(str(exc)) from None


def sync(node_id:str)->dict:
    return agent_transport.enqueue(node_id,"cert.status",ttl=180)


def queue_initial_check(node_id: str) -> bool:
    """Queue first TLS verification immediately; never depend on six-hour sweep.

    Safe to call from the first ready heartbeat or after registration. Never
    contacts Remnawave, SSH or the VPS synchronously. The agent handles the
    read-only cert.status task on its next outbound poll.
    """
    try:
        node=storage.get_node(node_id)
        if node["status"]!="ready":
            return False
        job=storage.get_install_job(node_id)
        if not job.get("remote_uuid") or not job.get("profile_uuid"):
            return False
        with storage.connect() as db:
            checked=db.execute(
                "SELECT last_checked,last_error FROM node_tls_sync WHERE node_id=?",
                (node_id,)).fetchone()
            if checked and (checked["last_checked"] or checked["last_error"]):
                return False
            prior=db.execute(
                """SELECT id FROM manager_agent_jobs
                   WHERE node_id=? AND action='cert.status' LIMIT 1""",
                (node_id,)).fetchone()
            if prior:
                return False
        agent_transport.enqueue(node_id,"cert.status",ttl=240)
        return True
    except (agent_transport.AgentError,LookupError):
        return False


def status()->dict:
    agents={a["id"]:a for a in agent_transport.nodes_status()}
    with storage.connect() as db:
        rows=db.execute("""SELECT n.id,n.code,n.domain,n.status,t.fingerprint,t.expires_at,
                   t.last_checked,t.last_applied,t.last_error,\n                   (SELECT COUNT(*) FROM manager_agent_jobs j WHERE j.node_id=n.id\n                    AND j.action='cert.status' AND j.status IN ('queued','leased')) AS pending\n                   FROM nodes n
                   LEFT JOIN node_tls_sync t ON n.id=t.node_id ORDER BY n.code""").fetchall()
    return {"mode":"node_local_paths","panel_mount_required":False,
            "check_interval_hours":6,"nodes":[{
            "id":r["id"],"code":r["code"],"domain":r["domain"],
            "status":r["status"],"expires_at":r["expires_at"] or 0,
            "last_checked":r["last_checked"] or 0,
            "last_applied":r["last_applied"] or 0,
            "last_error":r["last_error"] or "",
            "auto_sync":bool(agents.get(r["id"],{}).get("online")),
            "agent_installed":bool(agents.get(r["id"],{}).get("installed")),
            "checked":bool(r["fingerprint"]),\n            "checking":bool(r["pending"])} for r in rows]}


def background_cycle():
    for item in status()["nodes"]:
        if item["status"]!="ready" or not item["auto_sync"]:
            continue
        try:
            job=storage.get_install_job(item["id"])
            if not job.get("remote_uuid") or not job.get("profile_uuid"):
                continue
            agent_transport.enqueue(item["id"],"cert.status",ttl=240)
        except (agent_transport.AgentError,LookupError):
            pass


def start_background():
    global _STARTED
    with LOCK:
        if _STARTED:return
        _STARTED=True
    def worker():
        time.sleep(120)
        while True:
            try:background_cycle()
            except Exception:pass
            time.sleep(6*3600)
    threading.Thread(target=worker,name="agent-certbot-sync",daemon=True).start()
