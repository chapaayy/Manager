"""Node-only TLS certificate state and guarded one-profile migration."""
import re
import time
from copy import deepcopy
from email.utils import parsedate_to_datetime

from . import remnawave,storage,agent_transport,vps_install
from .template_engine import Endpoint


class LocalTLSError(ValueError):
    pass


def paths(domain):
    return {"keyFile":f"/opt/nginx/certs/{domain}_privkey.key",
            "certificateFile":f"/opt/nginx/certs/{domain}_fullchain.pem"}


def agent_status(node_id,data):
    node=storage.get_node(node_id)
    if node["status"]!="ready" or data.get("domain")!=node["domain"]:
        raise LocalTLSError("Нода или домен в отчёте агента не совпадают")
    if any(k in data for k in ("key","chain","certificate")):
        raise LocalTLSError("Передача PEM в режиме локальных TLS запрещена")
    fingerprint=data.get("certificate_sha256")
    details=data.get("details")
    if not isinstance(fingerprint,str) or not re.fullmatch("[0-9a-f]{64}",fingerprint):
        raise LocalTLSError("Агент не подтвердил отпечаток сертификата")
    if not isinstance(details,str) or len(details)>500 or "notAfter=" not in details:
        raise LocalTLSError("Агент не подтвердил срок действия сертификата")
    try:
        expires=int(parsedate_to_datetime(details.split("notAfter=",1)[1].splitlines()[0]).timestamp())
    except (ValueError,TypeError,OverflowError,IndexError):
        raise LocalTLSError("Невозможно прочитать срок действия TLS") from None
    if expires<int(time.time())+3600:
        raise LocalTLSError("TLS сертификат просрочен или скоро истечёт")
    return node,fingerprint,expires


def profile_slot(node,job):
    from . import node_cert_sync
    try:
        profile=node_cert_sync._profile(node,job)
        config=profile["config"]
        inbounds=[v for v in config.get("inbounds",[])
                  if isinstance(v,dict) and v.get("tag")==node["code"]+"_VLESS_TLS_IN"]
        if len(inbounds)!=1:
            raise LocalTLSError("TLS inbound не найден или неоднозначен")
        tls=inbounds[0].get("streamSettings",{}).get("tlsSettings",{})
        certs=tls.get("certificates")
        if not isinstance(certs,list) or len(certs)!=1 or not isinstance(certs[0],dict):
            raise LocalTLSError("TLS профиль нестандартный; изменение запрещено")
        return profile,certs
    except node_cert_sync.CertificateSyncError as exc:
        raise LocalTLSError(str(exc)) from None
    except (KeyError,TypeError,AttributeError):
        raise LocalTLSError("Remnawave вернула нестандартный профиль") from None


def update_status(node_id,fp,expires,changed):
    now=int(time.time())
    with storage.transaction() as db:
        db.execute("""INSERT INTO node_tls_sync(node_id,fingerprint,expires_at,last_checked,last_applied,last_error)
            VALUES(?,?,?,?,?,'') ON CONFLICT(node_id) DO UPDATE SET
            fingerprint=excluded.fingerprint,expires_at=excluded.expires_at,
            last_checked=excluded.last_checked,
            last_applied=CASE WHEN ? THEN excluded.last_applied ELSE node_tls_sync.last_applied END,
            last_error=''""",(node_id,fp,expires,now,now if changed else 0,int(changed)))
        storage.event(db,"tls.check",node_id,"Node-only TLS: reloaded" if changed else "Node-only TLS verified")


def report(node_id,data):
    node,fp,expires=agent_status(node_id,data)
    job=storage.get_install_job(node_id)
    if not job.get("remote_uuid") or not job.get("profile_uuid"):
        raise LocalTLSError("Нода не зарегистрирована")
    profile,certs=profile_slot(node,job)
    cert=certs[0]
    if cert!=paths(node["domain"]):
        if "key" in cert or "certificate" in cert:
            raise LocalTLSError("Профиль содержит PEM: сначала выполни миграцию на файловые пути")
        raise LocalTLSError("Пути сертификатов в профиле отличаются от файлов ноды")
    with storage.connect() as db:
        previous=db.execute("SELECT fingerprint,last_checked FROM node_tls_sync WHERE node_id=?",
                            (node_id,)).fetchone()
    changed=bool(previous and previous["last_checked"] and previous["fingerprint"]!=fp)
    if changed:
        try:
            remnawave.restart_node(job["remote_uuid"])
        except remnawave.PanelError:
            raise LocalTLSError("Не удалось перезапустить Xray этой ноды через Remnawave API") from None
    update_status(node_id,fp,expires,changed)
    return {"expires_at":expires,"fingerprint":fp,"updated":changed,"mode":"node_local_paths"}


def migration(node_id,code,cert_job_id,compose_job_id):
    node=storage.get_node(node_id)
    if code!=node["code"]:
        raise LocalTLSError("Подтверди точный код ноды")
    agents={v["id"]:v for v in agent_transport.nodes_status()}
    if not agents.get(node_id,{}).get("online"):
        raise LocalTLSError("Агент должен быть онлайн")
    job=storage.get_install_job(node_id)
    if node["status"]!="ready" or not job.get("remote_uuid") or not job.get("profile_uuid"):
        raise LocalTLSError("Нода не готова к миграции")
    for jid,action in ((cert_job_id,"cert.status"),(compose_job_id,"config.read")):
        if not isinstance(jid,str) or len(jid)>45:
            raise LocalTLSError("Нет свежей проверки агента")
        state=agent_transport.job_status(node_id,jid)
        if state["status"]!="done" or state["action"]!=action or time.time()-state["updated_at"]>300:
            raise LocalTLSError("Проверка агента не завершена или устарела")
    cert_data=agent_transport.job_status(node_id,cert_job_id)["result"]
    compose_data=agent_transport.job_status(node_id,compose_job_id)["result"]
    _,fp,expires=agent_status(node_id,cert_data)
    compose=compose_data.get("content")
    if compose_data.get("name")!="node-compose" or not isinstance(compose,str):
        raise LocalTLSError("Не проверен Docker Compose ноды")
    if not re.search(r"(?m)^\s*-\s*['\"]?/opt/nginx/certs:/opt/nginx/certs:ro['\"]?\s*$",compose):
        raise LocalTLSError("В Docker Compose ноды нет read-only mount сертификатов")
    profile,certs=profile_slot(node,job)
    original=profile["config"]
    cert=certs[0]
    expected=paths(node["domain"])
    if cert==expected:
        update_status(node_id,fp,expires,False)
        return {"migrated":False,"already_file_backed":True}
    if "keyFile" in cert or "certificateFile" in cert or "key" not in cert or "certificate" not in cert:
        raise LocalTLSError("Неизвестный TLS профиль: миграция запрещена")
    config=deepcopy(original)
    inbounds=[i for i in config["inbounds"] if i.get("tag")==node["code"]+"_VLESS_TLS_IN"]
    inbounds[0]["streamSettings"]["tlsSettings"]["certificates"]=[expected]
    # Original inline PEM remains in RAM only, for an immediate rollback.
    try:
        remnawave.replace_profile_config(job["profile_uuid"],config)
    except remnawave.PanelError:
        raise LocalTLSError("API отклонило локальные пути TLS") from None
    try:
        remnawave.restart_node(job["remote_uuid"])
        ready=False
        for i in range(12):
            if i:time.sleep(2)
            health=remnawave.node_health(job["remote_uuid"])
            if health["connected"] and health["xray_running"]:
                ready=True
                break
        if not ready:
            raise LocalTLSError("Xray не подтвердил запуск")
    except Exception:
        try:
            remnawave.replace_profile_config(job["profile_uuid"],original)
            remnawave.restart_node(job["remote_uuid"])
        except Exception:
            raise LocalTLSError("Миграция и автоматический откат не подтверждены; проверь профиль своей ноды") from None
        raise LocalTLSError("Проверка Xray после миграции не прошла; прежний профиль восстановлен") from None
    update_status(node_id,fp,expires,True)
    return {"migrated":True,"mode":"node_local_paths","panel_server_unchanged":True}
