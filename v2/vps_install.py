"""SSH preflight and supervised first Remnawave Node installation.

No password or node SECRET_KEY is persisted in the web database or logs.
Root SSH is allowed only after a read-only host-key probe and user approval.
Only CLEAN Ubuntu/Debian public IPv4 VPS are supported by this first installer.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import socket
import time

import paramiko

from . import remnawave, storage
from .template_engine import Endpoint, TemplateError, new_inbound, validate_rendered

POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="xppn-vps")
ROOT = Path(__file__).resolve().parent / "data"
SSH_TIMEOUT = 16
FP = re.compile(r"SHA256:[A-Za-z0-9+/]{42,44}\Z")
STEPS = (
    "Подключение по SSH", "Проверка чистого VPS", "Установка Docker и Nginx",
    "Выпуск TLS-сертификата", "Запуск Remnawave Node",
    "Создание Xray Config Profile", "Регистрация в Remnawave",
)


def check_ip(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Нужен числовой публичный IPv4-адрес VPS") from None
    if address.version != 4 or not address.is_global:
        raise ValueError("Для автоматической установки необходим публичный IPv4")
    return str(address)


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def ssh_open(ip: str, port: int, password: str, expected_fp: str | None = None):
    ip = check_ip(ip)
    if not 1 <= port <= 65535:
        raise ValueError("Неверный SSH-порт")
    if not 1 <= len(password) <= 512 or "\x00" in password:
        raise ValueError("Неверный SSH-пароль")
    sock = socket.create_connection((ip, port), timeout=SSH_TIMEOUT)
    connection = paramiko.Transport(sock, disabled_algorithms={"pubkeys": ["ssh-rsa"]})
    try:
        connection.banner_timeout = SSH_TIMEOUT
        connection.auth_timeout = SSH_TIMEOUT
        connection.start_client(timeout=SSH_TIMEOUT)
        fp = fingerprint(connection.get_remote_server_key())
        if expected_fp is not None and fp != expected_fp:
            raise ValueError("SSH-ключ изменился. Установка остановлена: сверь fingerprint в панели провайдера.")
        connection.auth_password("root", password, fallback=False)
        if not connection.is_authenticated():
            raise ValueError("SSH root авторизация не удалась")
        return connection, fp
    except Exception:
        connection.close()
        raise


def run_command(connection, command: str, *, timeout: int = 30, max_bytes: int = 16000) -> str:
    channel = connection.open_session(timeout=SSH_TIMEOUT)
    channel.settimeout(min(timeout, 120))
    try:
        channel.exec_command(command)
        chunks = []
        total = 0
        deadline = time.monotonic() + timeout
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            if time.monotonic() > deadline:
                raise TimeoutError("SSH-команда выполняется слишком долго")
            for ready, recv in ((channel.recv_ready, channel.recv),
                                (channel.recv_stderr_ready, channel.recv_stderr)):
                while ready():
                    data = recv(4096)
                    if not data:
                        break
                    total += len(data)
                    if total > max_bytes:
                        raise ValueError("Ответ сервера слишком большой")
                    chunks.append(data)
            time.sleep(0.05)
        rc = channel.recv_exit_status()
        if rc != 0:
            # Do not return command output for operations containing secrets.
            raise RuntimeError(f"Удалённая операция завершилась с кодом {rc}")
        return b"".join(chunks).decode(errors="replace")
    finally:
        channel.close()


READONLY = (
    "LC_ALL=C; . /etc/os-release 2>/dev/null; "
    "printf 'OS=%s\\n' \"$ID\"; "
    "printf 'VERSION=%s\\n' \"$VERSION_ID\"; "
    "printf 'UID=%s\\n' \"$(id -u)\"; "
    "printf 'ARCH=%s\\n' \"$(uname -m)\"; "
    "printf 'DISK=%s\\n' \"$(df -Pm / | tail -n 1 | awk '{print $4}')\"; "
    "printf 'NGINX_DIR=%s\\n' \"$(test -e /opt/nginx && echo yes || echo no)\"; "
    "printf 'NODE_DIR=%s\\n' \"$(test -e /opt/remnanode && echo yes || echo no)\"; "
    "echo 'PORTS_BEGIN'; "
    "ss -ltnH"
)


def preflight(ip: str, port: int, password: str, domain: str, expected_fp: str | None = None) -> dict:
    check_ip(ip)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}", domain) or len(domain)>253:
        raise ValueError("Укажи корректный домен VPS")
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(domain, 80, family=socket.AF_INET,
                                                   type=socket.SOCK_STREAM)}
    except OSError:
        raise ValueError("Домен VPS не имеет A-записи") from None
    if ip not in ips or len(ips) != 1:
        raise ValueError("A-запись домена должна однозначно указывать на IP этого VPS")
    connection, actual = ssh_open(ip, port, password, expected_fp)
    try:
        output = run_command(connection, READONLY)
    finally:
        connection.close()
    lines = output.splitlines()
    data = dict(line.split("=", 1) for line in lines if "=" in line and line.split("=", 1)[0] in
                {"OS","VERSION","UID","ARCH","DISK","NGINX_DIR","NODE_DIR"})
    ports = "\n".join(lines[lines.index("PORTS_BEGIN")+1:]) if "PORTS_BEGIN" in lines else ""
    occupied = sorted(p for p in (80,443,2222) if re.search(rf"(?<!\d):{p}\s", ports))
    warnings = []
    if data.get("OS") not in ("ubuntu","debian"):
        warnings.append("Поддерживаются только чистые Ubuntu и Debian")
    if data.get("UID") != "0":
        warnings.append("Первичная установка требует root")
    if data.get("ARCH") not in ("x86_64","aarch64"):
        warnings.append("Текущая архитектура не поддерживается")
    if int(data.get("DISK","0") or 0) < 2500:
        warnings.append("На диске требуется минимум 2,5 ГБ свободного места")
    if data.get("NGINX_DIR")=="yes" or data.get("NODE_DIR")=="yes":
        warnings.append("На VPS обнаружена прежняя установка Nginx/Remnawave; перезапись запрещена")
    if not ports.strip():
        warnings.append("Не удалось получить список занятых портов")
    if occupied:
        warnings.append("Порты заняты: "+", ".join(map(str,occupied)))
    return {
        "fingerprint": actual, "os": data.get("OS","?"), "version": data.get("VERSION","?"),
        "architecture": data.get("ARCH","?"), "free_disk_mb": int(data.get("DISK","0") or 0),
        "busy_ports": occupied, "warnings": warnings, "ready": not warnings,
        "read_only": True,
    }


def preview_plan(source: Endpoint) -> dict:
    """Public dry-run of the first direct VLESS TLS VPS; no credentials or SSH."""
    tag=source.code+"_VLESS_TLS_IN"
    inbound=new_inbound(tag,443,source.domain)
    proposed={
      "log":{"error":"/var/log/remnanode/error.log",
             "access":"/var/log/remnanode/access.log","loglevel":"warning"},
      "inbounds":[inbound],
      "outbounds":[{"tag":"DIRECT","protocol":"freedom"},
                   {"tag":"BLOCKED","protocol":"blackhole"}],
      "routing":{"rules":[
        {"type":"field","ip":["geoip:private"],"outboundTag":"BLOCKED"},
        {"type":"field","domain":["geosite:private"],"outboundTag":"BLOCKED"},
        {"type":"field","protocol":["bittorrent"],"outboundTag":"BLOCKED"},
        {"type":"field","inboundTag":[tag],"outboundTag":"DIRECT"}],
        "domainStrategy":"IPIfNonMatch"},
    }
    validate_rendered(proposed)
    return {
      "name":f"XPPN {source.code} · {source.country} · VLESS TLS",
      "xray":proposed,
      "nginx":(ROOT/"nginx.conf").read_text(encoding="utf-8").replace("{{source.domain}}",source.domain),
      "files":[
        "/opt/nginx/nginx.conf","/opt/nginx/docker-compose.yml",
        "/opt/nginx/certs/"+source.domain+"_fullchain.pem",
        "/opt/nginx/certs/"+source.domain+"_privkey.key",
        "/opt/remnanode/docker-compose.yml","/opt/remnanode/node.env"
      ],
      "variables":[
        {"key":"source.code","value":source.code},
        {"key":"source.domain","value":source.domain},
        {"key":"inbound.tag","value":tag},
        {"key":"tls.certificate","value":"Выпуск Let's Encrypt на VPS, ключ хранится зашифрованно"}
      ],
      "note":"Это предпросмотр. При установке Xray получает выпущенный TLS-сертификат; UUID пользователей добавляет Remnawave."
    }


def render_files(source: Endpoint, secret_key: str, panel_ip: str) -> dict:
    """Render allowlisted shipped artifacts; no arbitrary user-supplied shell."""
    if "\n" in secret_key or "\r" in secret_key:
        raise ValueError("Ключ Remnawave содержит недопустимые символы")
    panel_ip = check_ip(panel_ip)
    template = (ROOT/"nginx.conf").read_text(encoding="utf8")
    nginx = template.replace("{{source.domain}}", source.domain)
    if "{{" in nginx:
        raise ValueError("В nginx.conf остались неразрешённые переменные")
    html_site = ('<!doctype html><html lang="ru"><meta charset="utf-8">'
                 '<title>Welcome</title><body><h1>Service online</h1></body></html>\n')
    return {
        "domain": source.domain+"\n", "panel-ip": panel_ip+"\n",
        "nginx.conf": nginx,
        "nginx-compose.yml": (ROOT/"nginx-compose.yml").read_text(encoding="utf8"),
        "remnanode-compose.yml": (ROOT/"remnanode-compose.yml").read_text(encoding="utf8"),
        "node.env": "SECRET_KEY="+secret_key+"\n", "index.html": html_site,
        "remote-install.sh": (ROOT/"remote-install.sh").read_text(encoding="utf8"),
    }


def xray_config(source: Endpoint, cert: str, private_key: str) -> dict:
    """One VLESS TLS RAW direct exit, using settings from the supplied working bridge."""
    inbound = new_inbound(source.code+"_VLESS_TLS_IN",443,source.domain)
    certificates = inbound["streamSettings"]["tlsSettings"]["certificates"]
    # Inline PEM is supported by Xray-core; do not expose this generated config to the browser.
    certificates[:] = [{"certificate": cert.strip().splitlines(), "key": private_key.strip().splitlines()}]
    config = {
        "log": {"error":"/var/log/remnanode/error.log",
                "access":"/var/log/remnanode/access.log","loglevel":"warning"},
        "inbounds": [inbound],
        "outbounds": [{"tag":"DIRECT","protocol":"freedom"},
                      {"tag":"BLOCKED","protocol":"blackhole"}],
        "routing": {
            "rules": [
                {"type":"field","ip":["geoip:private"],"outboundTag":"BLOCKED"},
                {"type":"field","domain":["geosite:private"],"outboundTag":"BLOCKED"},
                {"type":"field","protocol":["bittorrent"],"outboundTag":"BLOCKED"},
                {"type":"field","inboundTag":[inbound["tag"]],"outboundTag":"DIRECT"},
            ],"domainStrategy":"IPIfNonMatch",
        }
    }
    validate_rendered(config)
    return config


def run_install_script(t, on_step):
    """Stream allowlisted progress labels only, never stdout with secret values."""
    channel=t.open_session(timeout=SSH_TIMEOUT)
    channel.settimeout(120)
    try:
        channel.exec_command("bash /root/.xppn-pending/remote-install.sh")
        buffer=""
        total=0
        deadline=time.monotonic()+1200
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            if time.monotonic()>deadline:
                raise TimeoutError("Установка VPS превысила 20 минут")
            for ready, recv in ((channel.recv_ready,channel.recv),
                                (channel.recv_stderr_ready,channel.recv_stderr)):
                while ready():
                    chunk=recv(16384)
                    if not chunk:break
                    total+=len(chunk)
                    if total>1500000:
                        raise RuntimeError("Слишком большой вывод удалённой установки")
                    buffer+=chunk.decode(errors="replace")
                    if len(buffer)>30000:
                        buffer=buffer[-30000:]
                    if "\n" in buffer:
                        lines=buffer.split("\n")
                        buffer=lines[-1]
                        for line in lines[:-1]:
                            if line.startswith("STEP: "):
                                on_step(line[6:150])
            time.sleep(0.1)
        rc=channel.recv_exit_status()
        if rc!=0:
            raise RuntimeError(f"Удалённая установка не завершилась успешно (код {rc}). Смотри VPS.")
    finally:
        channel.close()


def _stage_files(t, files: dict):
    run_command(t, "mkdir -p -m 0700 /root/.xppn-pending", timeout=15)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        for name, content in files.items():
            with sftp.file("/root/.xppn-pending/"+name,"wb") as target:
                target.write(content.encode("utf-8"))
            sftp.chmod("/root/.xppn-pending/"+name,0o600)
    finally:
        sftp.close()


def _read_remote_file(t, path: str, max_bytes: int = 20000) -> str:
    sftp=paramiko.SFTPClient.from_transport(t)
    try:
        with sftp.file(path,"rb") as src:
            data=src.read(max_bytes + 1)
            if len(data)>max_bytes:
                raise ValueError("Получен слишком большой сертификат")
            return data.decode("ascii")
    finally:
        sftp.close()


def deploy(node_id: str, ip: str, port: int, password: str,
           expected_fp: str, panel_ip: str):
    """Long-running worker. DB tracks truthful stages and errors. Secrets stay in memory."""
    node = storage.get_node(node_id)
    source = Endpoint(node["code"],node["domain"],node["country"])
    def stage(status: str, message: str):
        storage.set_install_status(node_id,status,message)
    try:
        stage("installing","Проверка доступа и чистоты VPS")
        outcome=preflight(ip,port,password,source.domain,expected_fp)
        if not outcome["ready"]:
            raise ValueError("; ".join(outcome["warnings"]))
        stage("installing","Запрашиваем ключ ноды из Remnawave")
        key=remnawave.node_secret()
        files=render_files(source,key,panel_ip)
        t,_=ssh_open(ip,port,password,expected_fp)
        try:
            _stage_files(t, files)
            stage("installing","Устанавливаем Docker, Nginx, TLS и Remnawave Node")
            # No user-controlled command text, no secrets on command line.
            run_install_script(t, lambda step: stage("installing", step))
            stage("installing","Получаем выпущенный TLS-сертификат")
            certificate=_read_remote_file(t,f"/opt/nginx/certs/{source.domain}_fullchain.pem")
            private_key=_read_remote_file(t,f"/opt/nginx/certs/{source.domain}_privkey.key")
        finally:
            t.close()
        stage("installing","Создаём отдельный Xray Config Profile")
        profile=remnawave.create_profile(
            f"XPPN {source.code} · {source.country} · VLESS TLS",
            xray_config(source,certificate,private_key))
        inbound_tag=source.code+"_VLESS_TLS_IN"
        selected=[i["uuid"] for i in profile["inbounds"] if i.get("tag")==inbound_tag]
        if len(selected)!=1:
            raise ValueError("Профиль создан, но Remnawave не подтвердила inbound "+inbound_tag)
        stage("installing","Регистрируем ноду в Remnawave")
        remote_id=remnawave.register_node(
            source.code,source.domain,source.country,profile["uuid"],selected)
        storage.set_install_status(node_id,"registered",
            "Нода зарегистрирована, ожидается подтверждение её связи с Remnawave",
            remote_uuid=remote_id,profile_uuid=profile["uuid"])
        # Do not mistake POST /api/nodes success for a working Xray instance.
        # Only mark ready when panel telemetry explicitly reports connectivity AND Xray.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                health = remnawave.node_health(remote_id)
                if health["connected"] and health["xray_running"]:
                    storage.set_install_status(
                        node_id,"ready",
                        "Remnawave подтвердила подключение и работу Xray ("+
                        (health["xray_version"] or "активен")+
                        "). Для клиентского доступа настрой Hosts и Internal Squads.")
                    break
            except remnawave.PanelError:
                pass
            time.sleep(3)
    except Exception as exc:
        # Never put SSH password, API token, PEM keys or SECRET_KEY in DB/logs.
        # Error messages from remote commands are intentionally reduced to exception class.
        if isinstance(exc, (ValueError, TemplateError, remnawave.PanelError)):
            detail=str(exc)
        else:
            detail=type(exc).__name__+": смотри состояние сервисов на VPS"
        for secret in (password,):
            detail=detail.replace(secret,"[СКРЫТО]") if secret else detail
        stage("failed",detail[:350])
    finally:
        # Zeroize caller-visible credential references as soon as possible.
        password = ""


def start_install(*, code: str, country: str, name: str, domain: str, role: str,
                  ip: str, port: int, password: str, fingerprint_value: str,
                  panel_ip: str) -> dict:
    if role not in ("regular","exit"):
        raise ValueError("Пока поддерживается установка обычной или выходной ноды. Вход моста требует связанного выходного сервера.")
    if not FP.fullmatch(fingerprint_value):
        raise ValueError("Нужно подтвердить SSH fingerprint из предварительной проверки")
    if not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,19}",code):
        raise ValueError("Некорректное имя ноды")
    check_ip(panel_ip)
    inspection=preflight(ip,port,password,domain,fingerprint_value)
    if not inspection["ready"]:
        raise ValueError("Установка отменена: "+"; ".join(inspection["warnings"]))
    # Check panel API and key before inserting anything or touching VPS.
    remnawave.node_secret()
    node=storage.create_node(code=code,name=name,domain=domain,country=country,role=role)
    try:
        storage.create_install_job(node["id"],ip,port,fingerprint_value)
    except Exception:
        # Transactional recovery if this IP is already queued under another name.
        with storage.transaction() as c:
            c.execute("DELETE FROM nodes WHERE id=? AND status='planned'",(node["id"],))
        raise
    POOL.submit(deploy,node["id"],ip,port,password,fingerprint_value,panel_ip)
    return {"node_id":node["id"],"stage":"queued","message":"Установка запущена"}
