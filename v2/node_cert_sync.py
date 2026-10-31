"""Node-owned TLS certificate lifecycle, with Remnawave used ONLY as an HTTP API.

The source of truth is Certbot on each VPS. Remnawave requires inline PEM in
its *API* Config Profiles unless it has local access to keyFile paths (not
assumed here). Never create or mount certificate files on the Panel VPS.

Only manager-created, dedicated per-node Xray profiles can be updated. Private
PEM content is never stored in this manager's database, logs or API responses.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import re
import socket
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import paramiko

from . import remnawave, storage, vps_install
from .template_engine import Endpoint

MAX_BUNDLE = 90000
LOCK = threading.RLock()
_STARTED = False


class CertificateSyncError(ValueError):
    pass


def validate_bundle(chain: bytes, key: bytes, domain: str) -> dict:
    if not chain or not key or len(chain) + len(key) > MAX_BUNDLE:
        raise CertificateSyncError("Файлы TLS отсутствуют или имеют неверный размер")
    if not (1 <= chain.count(b"-----BEGIN CERTIFICATE-----") <= 8):
        raise CertificateSyncError("Неверная цепочка сертификатов")
    try:
        certificate = x509.load_pem_x509_certificate(chain)
        private = serialization.load_pem_private_key(key, password=None)
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        pk = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ck = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, x509.ExtensionNotFound):
        raise CertificateSyncError("Не удалось проверить сертификат и приватный ключ") from None
    if pk != ck:
        raise CertificateSyncError("Приватный ключ не соответствует сертификату")
    if domain.lower() not in {item.lower() for item in san}:
        raise CertificateSyncError("TLS-сертификат выпущен для другого домена")
    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise CertificateSyncError("Сертификат недействителен")
    return {"fingerprint":hashlib.sha256(certificate.public_bytes(
                serialization.Encoding.DER)).hexdigest(),
            "expires_at":int(certificate.not_valid_after_utc.timestamp())}


def _installed_node(node_id: str):
    node = storage.get_node(node_id)
    job = storage.get_install_job(node_id)
    if node["status"] != "ready" or job["stage"] != "ready":
        raise CertificateSyncError("Нода должна быть полностью установлена и подключена")
    if not job.get("profile_uuid") or not job.get("remote_uuid"):
        raise CertificateSyncError("Отсутствует подтверждённая регистрация ноды")
    return node, job


def _bundle_from_password(node: dict, job: dict, password: str):
    t, _ = vps_install.ssh_open(job["ip"],job["port"],password,job["ssh_fingerprint"])
    try:
        chain = vps_install._read_remote_file(
            t, f"/opt/nginx/certs/{node['domain']}_fullchain.pem",max_bytes=70000)
        key = vps_install._read_remote_file(
            t, f"/opt/nginx/certs/{node['domain']}_privkey.key",max_bytes=16000)
        return chain.encode("ascii"),key.encode("ascii")
    finally:
        t.close()


EXPORTER = r'''#!/usr/bin/python3
import base64,json,pathlib,re,sys
try:
    domain=pathlib.Path("/opt/remnanode/domain").read_text().strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}",domain):
        raise ValueError("invalid domain")
    folder=pathlib.Path("/opt/nginx/certs")
    chain=(folder/(domain+"_fullchain.pem")).read_bytes()
    key=(folder/(domain+"_privkey.key")).read_bytes()
    if not chain or not key or len(chain)+len(key)>90000:raise ValueError("invalid sizes")
    print(json.dumps({"domain":domain,
        "chain":base64.b64encode(chain).decode(),
        "key":base64.b64encode(key).decode()},separators=(",",":")))
except Exception:
    print("CERT_EXPORT_FAILED",file=sys.stderr)
    sys.exit(1)
'''


def _key_connect(job: dict, pem: str):
    vps_install.check_ip(job["ip"])
    sock=socket.create_connection((job["ip"],job["port"]),timeout=vps_install.SSH_TIMEOUT)
    t=paramiko.Transport(sock)
    try:
        t.start_client(timeout=vps_install.SSH_TIMEOUT)
        if vps_install.fingerprint(t.get_remote_server_key())!=job["ssh_fingerprint"]:
            raise CertificateSyncError("SSH fingerprint ноды изменился")
        key=paramiko.RSAKey.from_private_key(io.StringIO(pem))
        t.auth_publickey("root",key)
        if not t.is_authenticated():
            raise CertificateSyncError("Сервер не принял SSH-ключ синхронизации")
        return t
    except Exception:
        t.close()
        raise


def _bundle_from_key(node: dict,job: dict,pem: str):
    t=_key_connect(job,pem)
    try:
        response=vps_install.run_command(t,"node-cert-export",timeout=25,max_bytes=135000)
        obj=json.loads(response)
        if not isinstance(obj,dict) or obj.get("domain")!=node["domain"]:
            raise CertificateSyncError("Домен ноды не совпадает с ответом SSH")
        return base64.b64decode(obj["chain"],validate=True),base64.b64decode(obj["key"],validate=True)
    except (KeyError,ValueError,TypeError,UnicodeDecodeError):
        raise CertificateSyncError("Недопустимый ответ службы сертификатов") from None
    finally:
        t.close()


def _record(node_id: str):
    with storage.connect() as db:
        r=db.execute("SELECT * FROM node_tls_sync WHERE node_id=?",(node_id,)).fetchone()
    return dict(r) if r else {}


def _profile_identity(node,job):
    """Dedicated profile must not be attached to any other node."""
    response=remnawave.request("GET","/api/nodes").get("response")
    if not isinstance(response,list):
        raise CertificateSyncError("Не удалось проверить привязки Xray-профилей")
    own=False
    for item in response:
        if not isinstance(item,dict):raise CertificateSyncError("Некорректный список нод Remnawave")
        active=item.get("configProfile")
        attached=(active.get("activeConfigProfileUuid") if isinstance(active,dict) else None)
        attached=attached or item.get("configProfileUuid") or item.get("activeConfigProfileUuid")
        if item.get("uuid")==job["remote_uuid"]:
            own=True
            if attached and attached!=job["profile_uuid"]:
                raise CertificateSyncError("У ноды изменился Xray-профиль")
        elif attached==job["profile_uuid"]:
            raise CertificateSyncError("Xray-профиль используется другой нодой")
        elif attached is None:
            # Cannot prove profile isolation: do not risk other nodes.
            raise CertificateSyncError("Не удалось исключить использование профиля другой нодой")
    if not own:
        raise CertificateSyncError("Нода не найдена в Remnawave")
    expected=vps_install.config_profile_name(Endpoint(node["code"],node["domain"],node["country"]))
    profile=remnawave.detailed_profile(job["profile_uuid"])
    if profile.get("name")!=expected:
        raise CertificateSyncError("Имя Xray-профиля изменено вручную; синхронизация запрещена")
    return profile


def _apply(node:dict,job:dict,chain:bytes,key:bytes,info:dict) -> bool:
    from copy import deepcopy
    profile=_profile_identity(node,job)
    original=profile["config"]
    desired=deepcopy(original)
    tag=node["code"]+"_VLESS_TLS_IN"
    inbounds=[inbound for inbound in desired.get("inbounds",[])
              if isinstance(inbound,dict) and inbound.get("tag")==tag]
    if len(inbounds)!=1:
        raise CertificateSyncError("Штатный TLS inbound не найден или дублируется")
    tls=inbounds[0].get("streamSettings",{}).get("tlsSettings",{})
    entries=tls.get("certificates")
    if not isinstance(entries,list) or len(entries)!=1 or not isinstance(entries[0],dict):
        raise CertificateSyncError("Нестандартная конфигурация TLS; автоматическая замена запрещена")
    current=entries[0]
    if "keyFile" in current or "certificateFile" in current:
        raise CertificateSyncError("Профиль использует файловый сертификат. Не меняем существующую схему.")
    if not ("key" in current and "certificate" in current):
        raise CertificateSyncError("В профиле нет штатного TLS-сертификата")
    chain_lines=chain.decode("ascii").strip().splitlines()
    key_lines=key.decode("ascii").strip().splitlines()
    # Avoid restarting Xray if this certificate was already applied manually.
    if current["key"]==key_lines and current["certificate"]==chain_lines:
        return False
    current["key"]=key_lines
    current["certificate"]=chain_lines
    # Do not return or log either config; both include a private key.
    patched=False
    try:
        remnawave.replace_profile_config(job["profile_uuid"],desired)
        patched=True
        remnawave.restart_node(job["remote_uuid"])
    except Exception:
        if patched:
            try:
                remnawave.replace_profile_config(job["profile_uuid"],original)
                remnawave.restart_node(job["remote_uuid"])
            except Exception:
                raise CertificateSyncError(
                    "Ошибка применения и отката TLS-конфига. Проверь ноду вручную") from None
        raise CertificateSyncError("Не удалось обновить TLS через Remnawave API") from None
    return True


def sync(node_id:str,password:str|None=None):
    node,job=_installed_node(node_id)
    with LOCK:
        row=_record(node_id)
        if password:
            chain,key=_bundle_from_password(node,job,password)
        elif row.get("sync_key_enc"):
            chain,key=_bundle_from_key(node,job,storage.decrypt(row["sync_key_enc"]))
        else:
            raise CertificateSyncError("Нет SSH-пароля и не настроена автосинхронизация")
        info=validate_bundle(chain,key,node["domain"])
        # Even unchanged certificate gets checked against the live API profile,
        # since it may have been changed by an operator after last sync.
        modified=_apply(node,job,chain,key,info)
        now=int(time.time())
        with storage.transaction() as db:
            db.execute("""INSERT INTO node_tls_sync
                (node_id,fingerprint,expires_at,last_checked,last_applied,last_error)
                VALUES(?,?,?,?,?, '')
                ON CONFLICT(node_id) DO UPDATE SET fingerprint=excluded.fingerprint,
                    expires_at=excluded.expires_at,last_checked=excluded.last_checked,
                    last_applied=CASE WHEN ? THEN excluded.last_applied ELSE node_tls_sync.last_applied END,
                    last_error=''""",
                (node_id,info["fingerprint"],info["expires_at"],now,now if modified else 0,int(modified)))
            storage.event(db,"tls.check",node_id,
                          "TLS certificate updated via API" if modified else "Node TLS certificate checked")
        return {"node_id":node_id,"domain":node["domain"],"expires_at":info["expires_at"],
                "updated":modified,"certificate_source":"node_certbot","panel_mount_required":False}


def enroll(node_id:str,password:str,confirmed:bool):
    """Add a forced-command root SSH key limited to reading this node's certs."""
    if not confirmed:raise CertificateSyncError("Подтверди установку ограниченного SSH-ключа")
    node,job=_installed_node(node_id)
    key=paramiko.RSAKey.generate(3072)
    stream=io.StringIO()
    key.write_private_key(stream)
    private_pem=stream.getvalue()
    comment="node-tls-sync-"+node["id"]
    public=key.get_name()+" "+key.get_base64()+" "+comment
    auth='command="/usr/bin/python3 /usr/local/libexec/node-tls-export.py",restrict '+public
    bootstrap=r'''#!/usr/bin/python3
import os,pathlib
base=pathlib.Path("/root/.ssh")
base.mkdir(mode=0o700,exist_ok=True)
os.chmod(base,0o700)
authorized=base/"authorized_keys"
before=authorized.read_text().splitlines() if authorized.exists() else []
new=pathlib.Path("/root/.node-tls-setup/key-line").read_text().strip()
comment=new.split()[-1]
updated=[entry for entry in before if not entry.rstrip().endswith(" "+comment)]
temp=base/".authorized_keys.node-tls"
fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w") as f:
    f.write("\n".join(updated+[new])+"\n")
    f.flush();os.fsync(f.fileno())
os.replace(temp,authorized)
'''
    t,_=vps_install.ssh_open(job["ip"],job["port"],password,job["ssh_fingerprint"])
    try:
        vps_install.run_command(t,"mkdir -p -m 0700 /root/.node-tls-setup /usr/local/libexec")
        sftp=paramiko.SFTPClient.from_transport(t)
        try:
            for path,text,mode in (
                ("/root/.node-tls-setup/key-line",auth,0o600),
                ("/root/.node-tls-setup/setup.py",bootstrap,0o600),
                ("/usr/local/libexec/node-tls-export.py",EXPORTER,0o700)):
                with sftp.file(path,"wb") as target: target.write(text.encode())
                sftp.chmod(path,mode)
        finally:sftp.close()
        vps_install.run_command(t,
            "python3 /root/.node-tls-setup/setup.py && rm -rf /root/.node-tls-setup")
    finally:t.close()
    # Confirm actual forced-command SSH login before persisting the key.
    chain,private=_bundle_from_key(node,job,private_pem)
    validate_bundle(chain,private,node["domain"])
    with storage.transaction() as db:
        db.execute("""INSERT INTO node_tls_sync(node_id,sync_key_enc) VALUES(?,?)
             ON CONFLICT(node_id) DO UPDATE SET sync_key_enc=excluded.sync_key_enc""",
             (node_id,storage.encrypt(private_pem)))
        storage.event(db,"tls.enroll",node_id,"Restricted node cert SSH key enrolled")
    return sync(node_id)


def status():
    with storage.connect() as db:
        data=db.execute("""SELECT n.id,n.code,n.domain,n.status,
            t.fingerprint,t.expires_at,t.last_checked,t.last_applied,
            t.last_error,t.sync_key_enc FROM nodes n
            LEFT JOIN node_tls_sync t ON n.id=t.node_id ORDER BY n.code""").fetchall()
    return {"mode":"node_local_certbot","panel_mount_required":False,
            "check_interval_hours":6,"nodes":[{
              "id":r["id"],"code":r["code"],"domain":r["domain"],
              "status":r["status"],"expires_at":r["expires_at"] or 0,
              "last_checked":r["last_checked"] or 0,
              "last_applied":r["last_applied"] or 0,
              "last_error":r["last_error"] or "",
              "auto_sync":bool(r["sync_key_enc"]),"checked":bool(r["fingerprint"])
            } for r in data]}


def background_cycle():
    for item in status()["nodes"]:
        if item["status"]!="ready" or not item["auto_sync"]:
            continue
        try:
            sync(item["id"])
        except Exception:
            with storage.transaction() as db:
                db.execute("""UPDATE node_tls_sync SET last_error=? WHERE node_id=?""",
                           ("Ошибка проверки сертификата/Remnawave API. Нода не изменена.",item["id"]))
                storage.event(db,"tls.error",item["id"],"TLS sync failed; inspect node and panel API")


def start_background():
    global _STARTED
    with LOCK:
        if _STARTED:return
        _STARTED=True
    def loop():
        time.sleep(120)
        while True:
            try:background_cycle()
            except Exception:pass
            time.sleep(6*3600)
    threading.Thread(name="node-local-tls",target=loop,daemon=True).start()
