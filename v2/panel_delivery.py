"""Pinned SSH certificate delivery to a Remnawave Panel on a SEPARATE VPS.

The installed root authorized_keys entry forces one narrow import command and
disallows pty, shell and TCP forwarding. No root password or API token is saved.
The receiver writes exclusively under /opt/xppn-panel-certs (panel bind mount).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import socket
import time

import paramiko

from . import storage, vps_install


class DeliveryError(ValueError):
    pass


IMPORTER = r'''#!/usr/bin/python3
import base64,hashlib,json,os,pathlib,re,secrets,sys
os.umask(0o077)
try:
    data=sys.stdin.buffer.read(180001)
    if len(data)>180000: raise ValueError("oversized transfer")
    obj=json.loads(data)
    code=obj["code"]
    domain=obj["domain"]
    if not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,19}",code): raise ValueError("invalid code")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}",domain): raise ValueError("invalid domain")
    cert=base64.b64decode(obj["certificate"],validate=True)
    key=base64.b64decode(obj["key"],validate=True)
    if not cert.startswith(b"-----BEGIN CERTIFICATE-----") or len(cert)+len(key)>85000:
        raise ValueError("invalid certificate")
    if b"-----BEGIN " not in key or b"PRIVATE KEY-----" not in key[:100]:
        raise ValueError("invalid key")
    digest=hashlib.sha256(cert+key).hexdigest()
    root=pathlib.Path("/opt/xppn-panel-certs")
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink(): raise ValueError("unsafe root")
    folder=root/code
    if folder.is_symlink(): raise ValueError("unsafe node")
    folder.mkdir(mode=0o700,exist_ok=True)
    current=folder/"current"
    if current.is_symlink() and current.resolve().parent==folder:
        if (current/"fullchain.pem").read_bytes()==cert and (current/"privkey.key").read_bytes()==key:
            print("OK "+digest)
            sys.exit(0)
    release=folder/(digest[:24]+"-"+secrets.token_hex(4))
    release.mkdir(mode=0o700)
    def save(path,content):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
    save(release/"fullchain.pem",cert)
    save(release/"privkey.key",key)
    tmp=folder/(".current-"+secrets.token_hex(4))
    tmp.symlink_to(release.name,target_is_directory=True)
    os.replace(tmp,current)
    print("OK "+digest)
except Exception:
    print("CERT_DELIVERY_FAILED",file=sys.stderr)
    sys.exit(1)
'''


def _settings() -> dict:
    with storage.connect() as db:
        row=db.execute("SELECT * FROM certificate_settings WHERE id=1").fetchone()
    return dict(row) if row else {}


def available() -> bool:
    row=_settings()
    return bool(row.get("mode")=="remote" and row.get("enabled")
                and row.get("remote_key_enc") and row.get("remote_ip")
                and row.get("remote_fingerprint"))


def _connect(ip: str, port: int, fingerprint: str, pem: str):
    vps_install.check_ip(ip)
    sock=socket.create_connection((ip,port),timeout=vps_install.SSH_TIMEOUT)
    t=paramiko.Transport(sock)
    try:
        t.start_client(timeout=vps_install.SSH_TIMEOUT)
        if vps_install.fingerprint(t.get_remote_server_key())!=fingerprint:
            raise DeliveryError("SSH fingerprint сервера панели изменился")
        t.auth_publickey("root",paramiko.RSAKey.from_private_key(io.StringIO(pem)))
        if not t.is_authenticated():
            raise DeliveryError("Сервер панели отклонил ключ синхронизации")
        return t
    except Exception:
        t.close()
        raise


def deliver(code: str, domain: str, fullchain: bytes, key: bytes):
    if not available():
        raise DeliveryError("Не настроено SSH-подключение к серверу Remnawave")
    row=_settings()
    t=_connect(row["remote_ip"],row["remote_port"],row["remote_fingerprint"],
               storage.decrypt(row["remote_key_enc"]))
    payload=json.dumps({"code":code,"domain":domain,
        "certificate":base64.b64encode(fullchain).decode(),
        "key":base64.b64encode(key).decode()},separators=(",",":")).encode()
    if len(payload)>180000:
        t.close()
        raise DeliveryError("Слишком большой сертификат")
    try:
        channel=t.open_session(timeout=vps_install.SSH_TIMEOUT)
        channel.settimeout(35)
        try:
            # The receiver is forced by authorized_keys, irrespective of command.
            channel.exec_command("xppn-panel-certificate-delivery")
            channel.sendall(payload)
            channel.shutdown_write()
            data=b""
            deadline=time.monotonic()+35
            while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
                if time.monotonic()>deadline: raise DeliveryError("Таймаут загрузки сертификата в панель")
                if channel.recv_ready():
                    data+=channel.recv(1024)
                    if len(data)>512: raise DeliveryError("Недопустимый ответ сервера панели")
                if channel.recv_stderr_ready():
                    channel.recv_stderr(1024)  # Never surface remote stderr
                time.sleep(0.05)
            if channel.recv_exit_status()!=0:
                raise DeliveryError("Сервер панели не принял сертификат")
            expected=("OK "+hashlib.sha256(fullchain+key).hexdigest()).encode()
            if data.strip()!=expected:
                raise DeliveryError("Сервер панели не подтвердил контрольную сумму")
        finally:
            channel.close()
    finally:
        t.close()


def enroll(ip: str, port: int, fingerprint: str, password: str, confirmed: bool):
    if not confirmed:
        raise DeliveryError("Подтверди установку ограниченного SSH-приёмника")
    if not vps_install.FP.fullmatch(fingerprint):
        raise DeliveryError("Укажи проверенный SSH fingerprint сервера панели")
    vps_install.check_ip(ip)
    if not 1<=port<=65535:
        raise DeliveryError("Неверный SSH-порт панели")
    with storage.connect() as db:
        if db.execute("SELECT 1 FROM node_certificates WHERE profile_mode='files' LIMIT 1").fetchone():
            raise DeliveryError("Перенастройка приёмника запрещена, пока есть файловые Xray-профили")
    key=paramiko.RSAKey.generate(3072)
    dest=io.StringIO()
    key.write_private_key(dest)
    private_pem=dest.getvalue()
    public=key.get_name()+" "+key.get_base64()+" xppn-panel-cert-receiver"
    auth='command="/usr/bin/python3 /usr/local/libexec/xppn-panel-cert-import.py",restrict '+public
    setup=r'''#!/usr/bin/python3
import os,pathlib
ssh=pathlib.Path("/root/.ssh")
ssh.mkdir(mode=0o700,exist_ok=True)
os.chmod(ssh,0o700)
target=ssh/"authorized_keys"
previous=target.read_text().splitlines() if target.exists() else []
authorized=(pathlib.Path("/root/.xppn-panel-bootstrap/authorized-line")).read_text().strip()
updated=[line for line in previous if not line.endswith("xppn-panel-cert-receiver")]
fd=os.open(target,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
with os.fdopen(fd,"w") as f: f.write("\n".join(updated+[authorized])+"\n")
'''
    t,_=vps_install.ssh_open(ip,port,password,fingerprint)
    try:
        vps_install.run_command(t,"mkdir -p -m 0700 /root/.xppn-panel-bootstrap /usr/local/libexec /opt/xppn-panel-certs")
        sftp=paramiko.SFTPClient.from_transport(t)
        try:
            for path,source,mode in (
                ("/root/.xppn-panel-bootstrap/authorized-line",auth,0o600),
                ("/root/.xppn-panel-bootstrap/setup.py",setup,0o600),
                ("/usr/local/libexec/xppn-panel-cert-import.py",IMPORTER,0o700)):
                with sftp.file(path,"wb") as stream: stream.write(source.encode())
                sftp.chmod(path,mode)
        finally:
            sftp.close()
        vps_install.run_command(t,
            "python3 /root/.xppn-panel-bootstrap/setup.py && rm -rf /root/.xppn-panel-bootstrap")
    finally:
        t.close()
    # Verify key-only authentication, without transferring any secret material.
    t=_connect(ip,port,fingerprint,private_pem)
    t.close()
    with storage.transaction() as db:
        db.execute("""UPDATE certificate_settings SET enabled=1,mode='remote',
                      remote_ip=?,remote_port=?,remote_fingerprint=?,remote_key_enc=?,
                      updated_at=strftime('%s','now') WHERE id=1""",
                   (ip,port,fingerprint,storage.encrypt(private_pem)))
        storage.event(db,"cert.panel.enroll","panel","Pinned restricted SSH receiver configured")
    return {"enabled":True,"mode":"remote","panel_ip":ip,"panel_port":port,
            "panel_mount_path":"/var/lib/remnawave/configs/xray/ssl/XPPN"}
