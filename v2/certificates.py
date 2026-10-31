"""Opt-in TLS certificate staging for the Remnawave panel.

Certificate bytes are NEVER exposed in HTTP JSON, log messages or SQLite.
This module cannot update a live Xray profile merely by staging certificates.
The panel must separately mount the shared host directory read-only.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import paramiko

from . import remnawave, storage, vps_install

PANEL_ROOT = "/var/lib/remnawave/configs/xray/ssl/XPPN"
CODE = re.compile(r"[A-Z][A-Z0-9_-]{1,19}\Z")
LOCK = threading.RLock()
MAX_BUNDLE = 85000


class CertError(ValueError):
    pass


def shared_dir() -> Path:
    """The manager must have the SAME host directory mounted as Remnawave."""
    location = os.environ.get("XPPN_V2_PANEL_CERT_DIR", "/panel-certs")
    if not location.startswith("/") or ".." in Path(location).parts:
        raise CertError("Некорректный каталог сертификатов")
    root = Path(location)
    if not root.is_dir() or root.is_symlink():
        raise CertError("Каталог сертификатов не подключён к менеджеру")
    if (root.stat().st_mode & stat.S_IWOTH):
        raise CertError("Каталог сертификатов доступен на запись посторонним")
    return root


def enabled() -> bool:
    try:
        with storage.connect() as db:
            row = db.execute("SELECT enabled FROM certificate_settings WHERE id=1").fetchone()
        return bool(row and row["enabled"]) and shared_dir().is_dir()
    except (CertError, OSError):
        return False


def configure(enabled_value: bool, confirmed_panel_mount: bool = False) -> dict:
    if enabled_value and not confirmed_panel_mount:
        raise CertError("Подтверди, что том xppn-v2-panel-certs подключён к Remnawave Panel")
    if enabled_value:
        shared_dir()
    else:
        with storage.connect() as db:
            if db.execute("SELECT 1 FROM node_certificates WHERE profile_mode='files' LIMIT 1").fetchone():
                raise CertError("Сначала верни файловые Xray-профили на прежние сертификаты")
    with storage.transaction() as db:
        db.execute("UPDATE certificate_settings SET enabled=?,updated_at=strftime('%s','now') WHERE id=1",
                   (int(enabled_value),))
        storage.event(db, "cert.settings", "panel",
                      "Certificate sharing enabled" if enabled_value else "Certificate sharing disabled")
    return status()


def paths(code: str) -> dict:
    if not CODE.fullmatch(code):
        raise CertError("Некорректный код сервера")
    prefix = PANEL_ROOT + "/" + code + "/current"
    return {"keyFile": prefix + "/privkey.key",
            "certificateFile": prefix + "/fullchain.pem"}


def _validate(fullchain: bytes, key: bytes, domain: str) -> dict:
    if not fullchain or not key or len(fullchain) + len(key) > MAX_BUNDLE:
        raise CertError("Файлы сертификата отсутствуют или слишком большие")
    if len(re.findall(rb"-----BEGIN CERTIFICATE-----", fullchain)) not in range(1, 9):
        raise CertError("Неверная цепочка сертификатов")
    try:
        leaf = x509.load_pem_x509_certificate(fullchain)
        private = serialization.load_pem_private_key(key, password=None)
        sans = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        pub = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cert_pub = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, x509.ExtensionNotFound) as e:
        raise CertError("Не удалось проверить TLS-сертификат и приватный ключ") from None
    if pub != cert_pub:
        raise CertError("Приватный ключ не соответствует сертификату")
    if domain.lower() not in {s.lower() for s in sans}:
        raise CertError("Сертификат выдан для другого домена")
    now = datetime.now(timezone.utc)
    if leaf.not_valid_before_utc > now or leaf.not_valid_after_utc <= now:
        raise CertError("Сертификат ещё не действителен или уже просрочен")
    return {"expires_at": int(leaf.not_valid_after_utc.timestamp()),
            "fingerprint": hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()}


def _write_file(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def publish(code: str, fullchain: bytes, key: bytes, domain: str) -> dict:
    """Atomic versioned publication. Previous active symlink survives failed writes."""
    info = _validate(fullchain, key, domain)
    with LOCK:
        root = shared_dir()
        folder = root / code
        if folder.is_symlink():
            raise CertError("Неподдерживаемая символическая ссылка для каталога ноды")
        folder.mkdir(mode=0o750, exist_ok=True)
        release = folder / (info["fingerprint"][:20] + "-" + secrets.token_hex(5))
        release.mkdir(mode=0o750)
        try:
            _write_file(release / "fullchain.pem", fullchain)
            _write_file(release / "privkey.key", key)
            temporary = folder / (".current-" + secrets.token_hex(5))
            temporary.symlink_to(release.name, target_is_directory=True)
            os.replace(temporary, folder / "current")
        except BaseException:
            # Existing release/active target always left untouched on failure.
            try:
                temporary.unlink(missing_ok=True)
            except UnboundLocalError:
                pass
            raise
        return info


def _remote_password_bundle(node: dict, job: dict, password: str):
    t, _ = vps_install.ssh_open(job["ip"], job["port"], password, job["ssh_fingerprint"])
    try:
        fullchain = vps_install._read_remote_file(
            t, f"/opt/nginx/certs/{node['domain']}_fullchain.pem", max_bytes=MAX_BUNDLE)
        key = vps_install._read_remote_file(
            t, f"/opt/nginx/certs/{node['domain']}_privkey.key", max_bytes=16000)
        return fullchain.encode("ascii"), key.encode("ascii")
    finally:
        t.close()


EXPORTER = r'''#!/usr/bin/python3
import base64, json, pathlib, re, sys
try:
    domain=pathlib.Path("/opt/remnanode/domain").read_text().strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}",domain): raise ValueError("invalid domain")
    root=pathlib.Path("/opt/nginx/certs")
    chain=(root/(domain+"_fullchain.pem")).read_bytes()
    key=(root/(domain+"_privkey.key")).read_bytes()
    if len(chain)+len(key)>85000: raise ValueError("too large")
    print(json.dumps({"domain":domain,"certificate":base64.b64encode(chain).decode(),
                      "key":base64.b64encode(key).decode()},separators=(",",":")))
except Exception:
    print("CERT_EXPORT_FAILED",file=sys.stderr)
    sys.exit(1)
'''


def _key_session(job: dict, pem: str):
    """Same pinned SSH fingerprint as initial install. Forced command only."""
    ip, port = job["ip"], job["port"]
    vps_install.check_ip(ip)
    raw = socket.create_connection((ip, port), timeout=vps_install.SSH_TIMEOUT)
    transport = paramiko.Transport(raw)
    try:
        transport.start_client(timeout=vps_install.SSH_TIMEOUT)
        if vps_install.fingerprint(transport.get_remote_server_key()) != job["ssh_fingerprint"]:
            raise CertError("SSH fingerprint изменился. Синхронизация остановлена")
        private = paramiko.RSAKey.from_private_key(io.StringIO(pem))
        transport.auth_publickey("root", private)
        if not transport.is_authenticated():
            raise CertError("Ключ синхронизации отклонён сервером")
        return transport
    except Exception:
        transport.close()
        raise


def _remote_key_bundle(node: dict, job: dict, pem: str):
    t = _key_session(job, pem)
    try:
        # The authorized_keys forced command ignores this requested command.
        payload = vps_install.run_command(t, "xppn-cert-export", timeout=25, max_bytes=120000)
        obj = json.loads(payload)
        if obj.get("domain") != node["domain"]:
            raise CertError("Домен синхронизации не совпадает с нодой")
        return (base64.b64decode(obj["certificate"], validate=True),
                base64.b64decode(obj["key"], validate=True))
    except (KeyError, ValueError, TypeError):
        raise CertError("Неправильный ответ службы сертификатов VPS") from None
    finally:
        t.close()


def _db_row(node_id: str) -> dict:
    with storage.connect() as db:
        row = db.execute("SELECT * FROM node_certificates WHERE node_id=?", (node_id,)).fetchone()
    return dict(row) if row else {}


def save_status(node_id: str, info: dict, changed: bool):
    with storage.transaction() as db:
        db.execute("""INSERT INTO node_certificates
                (node_id, expires_at, fingerprint, last_synced, last_error, updated_at)
                VALUES(?,?,?,?,?,strftime('%s','now'))
                ON CONFLICT(node_id) DO UPDATE SET
                expires_at=excluded.expires_at,fingerprint=excluded.fingerprint,
                last_synced=excluded.last_synced,last_error='',
                updated_at=excluded.updated_at""",
                (node_id, info["expires_at"], info["fingerprint"],
                 int(datetime.now(timezone.utc).timestamp()), ""))
        storage.event(db, "cert.sync", node_id,
                      "Panel certificate files staged" if changed else "Certificate already staged")


def sync(node_id: str, password: str | None = None) -> dict:
    if not enabled():
        raise CertError("Файловая синхронизация выключена: настрой общий каталог панели")
    node = storage.get_node(node_id)
    if node["status"] not in ("ready", "registered", "failed", "interrupted"):
        raise CertError("Синхронизация доступна только после установки VPS")
    job = storage.get_install_job(node_id)
    row = _db_row(node_id)
    if password:
        fullchain, key = _remote_password_bundle(node, job, password)
    elif row.get("sync_key_enc"):
        fullchain, key = _remote_key_bundle(node, job, storage.decrypt(row["sync_key_enc"]))
    else:
        raise CertError("Не указан SSH-пароль и не подключён автоматический доступ")
    info = _validate(fullchain, key, node["domain"])
    previous = row.get("fingerprint")
    # Publication is done every time, even if DB says the same fingerprint but files were removed.
    result = publish(node["code"], fullchain, key, node["domain"])
    changed = previous != result["fingerprint"]
    save_status(node_id, result, changed)
    if row.get("profile_mode") == "files" and row.get("applied_fingerprint") != result["fingerprint"]:
        # Remnawave must read the new files when re-sending the node configuration.
        # Never restart when the new bundle is invalid or has not been staged.
        remnawave.restart_node(job["remote_uuid"])
        with storage.transaction() as db:
            db.execute("""UPDATE node_certificates SET applied_fingerprint=?,
                          last_applied=strftime('%s','now') WHERE node_id=?""",
                       (result["fingerprint"],node_id))
            storage.event(db,"cert.profile.renew",node_id,"Updated TLS bundle sent for node restart")
    return {"node_id": node_id, "domain":node["domain"],
            "expires_at": result["expires_at"], "changed":changed,
            "panel_paths":paths(node["code"]), "staged":True}


def enroll(node_id: str, password: str, confirmed: bool) -> dict:
    """Install a root forced-command key; cannot open a root shell or forward ports."""
    if not confirmed:
        raise CertError("Подтверди подключение безопасного автоматического доступа")
    if not enabled():
        raise CertError("Сначала подключи каталог сертификатов панели")
    node = storage.get_node(node_id)
    job = storage.get_install_job(node_id)
    if node["status"] not in ("ready", "registered"):
        raise CertError("Автосинхронизация только для зарегистрированных нод")
    key = paramiko.RSAKey.generate(3072)
    out = io.StringIO()
    key.write_private_key(out)
    private_pem = out.getvalue()
    pub = key.get_name() + " " + key.get_base64() + " xppn-sync-" + node["id"]
    auth = ('command="/usr/bin/python3 /usr/local/libexec/xppn-cert-export.py",restrict ' + pub)
    bootstrap = r'''#!/usr/bin/python3
import os, pathlib
marker="xppn-sync-"
ssh=pathlib.Path("/root/.ssh")
ssh.mkdir(mode=0o700, exist_ok=True)
os.chmod(ssh,0o700)
target=ssh/"authorized_keys"
existing=target.read_text().splitlines() if target.exists() else []
new=(pathlib.Path("/root/.xppn-cert-bootstrap/authorized-line")).read_text().strip()
# Remove only the previous key for the SAME registered node.
comment=new.split()[-1]
entries=[line for line in existing if not line.rstrip().endswith(comment)]
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w") as f:
    f.write("\n".join(entries+[new])+"\n")
'''
    t, _ = vps_install.ssh_open(job["ip"], job["port"], password, job["ssh_fingerprint"])
    try:
        vps_install.run_command(t, "mkdir -p -m 0700 /root/.xppn-cert-bootstrap /usr/local/libexec")
        sftp = paramiko.SFTPClient.from_transport(t)
        try:
            for name,data in (("authorized-line",auth),("setup.py",bootstrap)):
                path="/root/.xppn-cert-bootstrap/"+name
                with sftp.file(path,"wb") as dest: dest.write(data.encode())
                sftp.chmod(path,0o600)
            with sftp.file("/usr/local/libexec/xppn-cert-export.py","wb") as dest:
                dest.write(EXPORTER.encode())
            sftp.chmod("/usr/local/libexec/xppn-cert-export.py",0o700)
        finally:
            sftp.close()
        vps_install.run_command(t, "python3 /root/.xppn-cert-bootstrap/setup.py && rm -rf /root/.xppn-cert-bootstrap")
    finally:
        t.close()
    # The stored private key is encrypted. Test forced-command access first.
    _remote_key_bundle(node,job,private_pem)
    with storage.transaction() as db:
        db.execute("""INSERT INTO node_certificates(node_id,sync_key_enc,updated_at)
                      VALUES(?,?,strftime('%s','now')) ON CONFLICT(node_id)
                      DO UPDATE SET sync_key_enc=excluded.sync_key_enc,
                                    updated_at=excluded.updated_at""",
                   (node_id,storage.encrypt(private_pem)))
        storage.event(db, "cert.enroll", node_id, "Certificate-only SSH key enrolled")
    return sync(node_id)


def _profile_candidate(node_id: str) -> tuple[dict, dict, dict, str]:
    """Read and transform only the Manager-owned TLS inbound, preserving all routes."""
    if not enabled():
        raise CertError("Файловая синхронизация выключена")
    node = storage.get_node(node_id)
    job = storage.get_install_job(node_id)
    row = _db_row(node_id)
    if node["status"] != "ready" or not job["profile_uuid"] or not job["remote_uuid"]:
        raise CertError("Профиль ещё не принадлежит работающей ноде")
    now = int(datetime.now(timezone.utc).timestamp())
    if not row.get("last_synced") or row["expires_at"] <= now+86400:
        raise CertError("Сначала синхронизируй действующий TLS-сертификат")
    if not (shared_dir()/node["code"]/"current"/"fullchain.pem").is_file():
        raise CertError("Сертификат отсутствует в общем томе")
    # Reject profiles that might be shared or have been edited beyond our known identity.
    profile = remnawave.detailed_profile(job["profile_uuid"])
    expected = vps_install.config_profile_name(
        vps_install.Endpoint(node["code"],node["domain"],node["country"]))
    if profile.get("name") != expected:
        raise CertError("Название Xray-профиля изменено вручную. Автоматическая миграция запрещена")
    from copy import deepcopy
    current = profile["config"]
    desired = deepcopy(current)
    inbound_tag = node["code"]+"_VLESS_TLS_IN"
    inbounds = [i for i in desired.get("inbounds",[]) if isinstance(i,dict) and i.get("tag")==inbound_tag]
    if len(inbounds)!=1:
        raise CertError("Не найден единственный штатный VLESS inbound ноды")
    tls = inbounds[0].get("streamSettings",{}).get("tlsSettings",{})
    entries = tls.get("certificates")
    if not isinstance(entries,list) or len(entries)!=1 or not isinstance(entries[0],dict):
        raise CertError("Нестандартный TLS-конфиг; автоматическая миграция запрещена")
    if entries[0].get("keyFile") == paths(node["code"])["keyFile"]:
        raise CertError("Профиль уже использует файловые сертификаты")
    if not ("key" in entries[0] and "certificate" in entries[0]):
        raise CertError("Ожидаемый встроенный TLS-ключ в профиле не найден")
    # Change only these 2 fields, preserve any additional certificate options.
    entry=entries[0]
    entry.pop("key",None)
    entry.pop("certificate",None)
    entry.update(paths(node["code"]))
    signature=hashlib.sha256(json.dumps(current,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return node,job,{"original":current,"new":desired},signature


def migration_preview(node_id: str) -> dict:
    node,job,config,signature=_profile_candidate(node_id)
    return {"node_id":node_id,"code":node["code"],
            "profile_uuid":job["profile_uuid"],"sha256":signature,
            "panel_paths":paths(node["code"]),"changes":"Только сертификат указанного inbound",
            "requires_confirmation":True}


def migrate_profile(node_id: str, expected_sha256: str, confirmed: bool) -> dict:
    """Explicit opt-in. Save encrypted rollback before changing a live profile."""
    if not confirmed:
        raise CertError("Подтверди переключение работающего Xray-профиля")
    if not re.fullmatch(r"[0-9a-f]{64}",expected_sha256):
        raise CertError("Неверная контрольная сумма конфигурации")
    with LOCK:
        node,job,config,signature=_profile_candidate(node_id)
        if signature != expected_sha256:
            raise CertError("Профиль Remnawave изменился. Повтори предварительную проверку")
        with storage.transaction() as db:
            row=db.execute("SELECT profile_mode FROM node_certificates WHERE node_id=?",(node_id,)).fetchone()
            if not row or row["profile_mode"]!="inline":
                raise CertError("Файловый режим уже включён или состояние не определено")
            db.execute("""INSERT INTO cert_profile_backups
                          (node_id,config_enc,profile_uuid,created_at)
                          VALUES(?,?,?,strftime('%s','now'))
                          ON CONFLICT(node_id) DO UPDATE SET
                          config_enc=excluded.config_enc,profile_uuid=excluded.profile_uuid,
                          created_at=excluded.created_at""",
                       (node_id,storage.encrypt(json.dumps(config["original"])),job["profile_uuid"]))
            storage.event(db,"cert.profile.backup",node_id,"Encrypted Xray rollback snapshot created")
        applied=False
        try:
            remnawave.replace_profile_config(job["profile_uuid"],config["new"])
            applied=True
            remnawave.restart_node(job["remote_uuid"])
        except Exception:
            if applied:
                try:
                    remnawave.replace_profile_config(job["profile_uuid"],config["original"])
                    remnawave.restart_node(job["remote_uuid"])
                except Exception:
                    raise CertError("Ошибка переключения и отката профиля. Проверь Remnawave вручную") from None
            raise CertError("Переключение отклонено, предыдущая конфигурация сохранена") from None
        with storage.transaction() as db:
            db.execute("""UPDATE node_certificates SET profile_mode='files',
                          last_applied=strftime('%s','now'), applied_fingerprint=fingerprint
                          WHERE node_id=?""",(node_id,))
            storage.event(db,"cert.profile.files",node_id,"Xray profile switched to panel-mounted certificate paths")
        return {"node_id":node_id,"mode":"files","restart_requested":True,
                "message":"Профиль переключён, запрошен перезапуск ноды. Проверь TLS-клиентов."}


def restore_profile(node_id: str, confirmed: bool) -> dict:
    """Manual rollback using an encrypted snapshot. Does not delete staged certs."""
    if not confirmed:
        raise CertError("Подтверди восстановление прежнего Xray-профиля")
    node=storage.get_node(node_id)
    job=storage.get_install_job(node_id)
    with LOCK:
        with storage.connect() as db:
            backup=db.execute("SELECT * FROM cert_profile_backups WHERE node_id=?",(node_id,)).fetchone()
        if not backup or backup["profile_uuid"]!=job["profile_uuid"] or not job["remote_uuid"]:
            raise CertError("Резервная копия конфигурации не найдена")
        old=json.loads(storage.decrypt(backup["config_enc"]))
        remnawave.replace_profile_config(job["profile_uuid"],old)
        remnawave.restart_node(job["remote_uuid"])
        with storage.transaction() as db:
            db.execute("UPDATE node_certificates SET profile_mode='inline',applied_fingerprint='',last_applied=strftime('%s','now') WHERE node_id=?",(node_id,))
            storage.event(db,"cert.profile.restore",node_id,"Previous Xray profile restored")
        return {"node_id":node_id,"mode":"inline","restart_requested":True}


def status() -> dict:
    rows=[]
    with storage.connect() as db:
        result=db.execute("""SELECT n.id,n.code,n.domain,n.status,c.expires_at,
                          c.last_synced,c.last_error,c.fingerprint,c.sync_key_enc,c.profile_mode,c.last_applied,c.applied_fingerprint
                          FROM nodes n LEFT JOIN node_certificates c ON c.node_id=n.id
                          ORDER BY n.code""").fetchall()
    for r in result:
        rows.append({"id":r["id"],"code":r["code"],"domain":r["domain"],
                     "node_status":r["status"],"expires_at":r["expires_at"] or 0,
                     "last_synced":r["last_synced"] or 0,
                     "last_error":r["last_error"] or "",
                     "auto_sync":bool(r["sync_key_enc"]), "staged":bool(r["fingerprint"]),
                     "profile_mode":r["profile_mode"] or "inline",
                     "last_applied":r["last_applied"] or 0,
                     "restart_pending":bool(r["profile_mode"]=="files" and r["fingerprint"]!=r["applied_fingerprint"]),
                     "panel_paths":paths(r["code"])})
    return {"enabled": enabled(), "panel_dir":PANEL_ROOT,
            "nodes":rows, "automatic_refresh_interval_hours":6}


def background_cycle():
    if not enabled():
        return
    for node in status()["nodes"]:
        if not node["auto_sync"] or node["node_status"] != "ready":
            continue
        try:
            sync(node["id"])
        except Exception:
            # Never store remote stderr, private material, SSH passwords or API payloads.
            with storage.transaction() as db:
                db.execute("UPDATE node_certificates SET last_error=?,updated_at=strftime('%s','now') WHERE node_id=?",
                           ("Не удалось обновить сертификат. Проверь SSH, доступность VPS и монтирование.",node["id"]))
                storage.event(db,"cert.sync.error",node["id"],"Certificate sync failed")


_BACKGROUND_STARTED = False


def start_background():
    """Six-hour best-effort polling. Nothing is touched unless admin enabled sync."""
    global _BACKGROUND_STARTED
    with LOCK:
        if _BACKGROUND_STARTED:
            return
        _BACKGROUND_STARTED = True
    def worker():
        time.sleep(120)
        while True:
            try:
                background_cycle()
            except Exception:
                pass
            time.sleep(6 * 3600)
    threading.Thread(target=worker, name="xppn-certificate-sync", daemon=True).start()
