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

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import paramiko

from . import storage, vps_install

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


def status() -> dict:
    rows=[]
    with storage.connect() as db:
        result=db.execute("""SELECT n.id,n.code,n.domain,n.status,c.expires_at,
                          c.last_synced,c.last_error,c.fingerprint,c.sync_key_enc
                          FROM nodes n LEFT JOIN node_certificates c ON c.node_id=n.id
                          ORDER BY n.code""").fetchall()
    for r in result:
        rows.append({"id":r["id"],"code":r["code"],"domain":r["domain"],
                     "node_status":r["status"],"expires_at":r["expires_at"] or 0,
                     "last_synced":r["last_synced"] or 0,
                     "last_error":r["last_error"] or "",
                     "auto_sync":bool(r["sync_key_enc"]), "staged":bool(r["fingerprint"]),
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
