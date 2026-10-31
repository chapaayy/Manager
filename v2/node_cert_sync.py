"""Node-owned Certbot certificates. Agent-only transport; never SSH after setup.

Remnawave Panel is only an API provider. No certificate mounts on Panel.
Certificate PEM passes in memory from authenticated agent to Remnawave API,
never via a user-facing endpoint and never into the Manager database.
"""
import base64
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from . import agent_transport, remnawave, storage, vps_install
from .template_engine import Endpoint

LOCK=threading.RLock()
_STARTED=False


class CertificateSyncError(ValueError):
    pass


def validate_bundle(chain:bytes,key:bytes,domain:str)->dict:
    if not chain or not key or len(chain)+len(key)>90000:
        raise CertificateSyncError("Отсутствует TLS сертификат или ключ")
    if not (1<=chain.count(b"-----BEGIN CERTIFICATE-----")<=8):
        raise CertificateSyncError("Неверная цепочка TLS сертификатов")
    try:
        leaf=x509.load_pem_x509_certificate(chain)
        private=serialization.load_pem_private_key(key,password=None)
        names=leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        pub=private.public_key().public_bytes(
            serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        cert_pub=leaf.public_key().public_bytes(
            serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError,TypeError,x509.ExtensionNotFound):
        raise CertificateSyncError("Не удалось проверить TLS сертификат") from None
    if pub!=cert_pub:
        raise CertificateSyncError("TLS ключ не соответствует сертификату")
    if domain.lower() not in {s.lower() for s in names}:
        raise CertificateSyncError("TLS сертификат выпущен для другого домена")
    now=datetime.now(timezone.utc)
    if leaf.not_valid_before_utc>now or leaf.not_valid_after_utc<=now:
        raise CertificateSyncError("TLS сертификат недействителен")
    return {"fingerprint":hashlib.sha256(
        leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "expires_at":int(leaf.not_valid_after_utc.timestamp())}


def _profile(node,job):
    rows=remnawave.request("GET","/api/nodes").get("response")
    if not isinstance(rows,list):
        raise CertificateSyncError("Не удалось проверить привязку Xray профиля")
    own=False
    for n in rows:
        if not isinstance(n,dict):raise CertificateSyncError("Некорректный ответ Remnawave")
        active=n.get("configProfile")
        attached=active.get("activeConfigProfileUuid") if isinstance(active,dict) else None
        attached=attached or n.get("configProfileUuid") or n.get("activeConfigProfileUuid")
        if n.get("uuid")==job["remote_uuid"]:
            own=True
            if attached and attached!=job["profile_uuid"]:
                raise CertificateSyncError("Нода использует другой Xray профиль")
        elif attached==job["profile_uuid"]:
            raise CertificateSyncError("Xray профиль используется другой нодой")
        elif attached is None:
            raise CertificateSyncError("Не удалось подтвердить изоляцию Xray профиля")
    if not own:
        raise CertificateSyncError("Нода отсутствует в Remnawave")
    data=remnawave.detailed_profile(job["profile_uuid"])
    expected=vps_install.config_profile_name(Endpoint(
        node["code"],node["domain"],node["country"]))
    if data.get("name")!=expected:
        raise CertificateSyncError("Неожиданное имя Xray профиля")
    return data


def _apply(node,job,chain,key):
    profile=_profile(node,job)
    original=profile["config"]
    target=deepcopy(original)
    matched=[i for i in target.get("inbounds",[])
             if isinstance(i,dict) and i.get("tag")==node["code"]+"_VLESS_TLS_IN"]
    if len(matched)!=1:
        raise CertificateSyncError("Штатный TLS inbound не найден")
    certificates=matched[0].get("streamSettings",{}).get("tlsSettings",{}).get("certificates")
    if not isinstance(certificates,list) or len(certificates)!=1 or not isinstance(certificates[0],dict):
        raise CertificateSyncError("Нестандартный TLS профиль")
    cert=certificates[0]
    # Never replace a working file-backed profile with inline PEM without consent.
    if "keyFile" in cert or "certificateFile" in cert:
        raise CertificateSyncError("Файловый Xray профиль оставлен без изменений")
    if "key" not in cert or "certificate" not in cert:
        raise CertificateSyncError("TLS сертификат не встроен в профиль")
    chain_lines=chain.decode("ascii").strip().splitlines()
    key_lines=key.decode("ascii").strip().splitlines()
    if cert["key"]==key_lines and cert["certificate"]==chain_lines:
        return False
    cert["key"]=key_lines
    cert["certificate"]=chain_lines
    patched=False
    try:
        remnawave.replace_profile_config(job["profile_uuid"],target)
        patched=True
        remnawave.restart_node(job["remote_uuid"])
    except Exception:
        if patched:
            try:
                remnawave.replace_profile_config(job["profile_uuid"],original)
                remnawave.restart_node(job["remote_uuid"])
            except Exception:
                raise CertificateSyncError("Ошибка применения и отката TLS профиля") from None
        raise CertificateSyncError("Не удалось обновить TLS профиль через API") from None
    return True


def apply_agent_export(node_id:str,data:dict)->dict:
    """Invoked only inside the authenticated agent result endpoint."""
    node=storage.get_node(node_id)
    job=storage.get_install_job(node_id)
    if node["status"]!="ready" or not job.get("remote_uuid") or not job.get("profile_uuid"):
        raise CertificateSyncError("Нода не готова для обновления TLS")
    if data.get("domain")!=node["domain"]:
        raise CertificateSyncError("Неправильный домен в отчёте агента")
    try:
        chain=base64.b64decode(data["chain"],validate=True)
        key=base64.b64decode(data["key"],validate=True)
    except (KeyError,ValueError,TypeError):
        raise CertificateSyncError("Агент передал некорректный TLS сертификат") from None
    info=validate_bundle(chain,key,node["domain"])
    with LOCK:
        changed=_apply(node,job,chain,key)
        now=int(time.time())
        with storage.transaction() as db:
            db.execute("""INSERT INTO node_tls_sync
                 (node_id,fingerprint,expires_at,last_checked,last_applied,last_error)
                 VALUES(?,?,?,?,?,'')
                 ON CONFLICT(node_id) DO UPDATE SET
                 fingerprint=excluded.fingerprint,expires_at=excluded.expires_at,
                 last_checked=excluded.last_checked,
                 last_applied=CASE WHEN ? THEN excluded.last_applied ELSE node_tls_sync.last_applied END,
                 last_error=''""",
                 (node_id,info["fingerprint"],info["expires_at"],now,now if changed else 0,int(changed)))
            storage.event(db,"tls.check",node_id,"Agent-applied node TLS" if changed else "Agent verified node TLS")
    return {"expires_at":info["expires_at"],
            "fingerprint":info["fingerprint"],"updated":changed}


def sync(node_id:str)->dict:
    return agent_transport.enqueue(node_id,"cert.export",ttl=180)


def status()->dict:
    agents={a["id"]:a for a in agent_transport.nodes_status()}
    with storage.connect() as db:
        rows=db.execute("""SELECT n.id,n.code,n.domain,n.status,t.fingerprint,t.expires_at,
                   t.last_checked,t.last_applied,t.last_error FROM nodes n
                   LEFT JOIN node_tls_sync t ON n.id=t.node_id ORDER BY n.code""").fetchall()
    return {"mode":"node_local_certbot_agent","panel_mount_required":False,
            "check_interval_hours":6,"nodes":[{
            "id":r["id"],"code":r["code"],"domain":r["domain"],
            "status":r["status"],"expires_at":r["expires_at"] or 0,
            "last_checked":r["last_checked"] or 0,
            "last_applied":r["last_applied"] or 0,
            "last_error":r["last_error"] or "",
            "auto_sync":bool(agents.get(r["id"],{}).get("online")),
            "agent_installed":bool(agents.get(r["id"],{}).get("installed")),
            "checked":bool(r["fingerprint"])} for r in rows]}


def background_cycle():
    for item in status()["nodes"]:
        if item["status"]!="ready" or not item["auto_sync"]:
            continue
        try:
            agent_transport.enqueue(item["id"],"cert.export",ttl=240)
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
