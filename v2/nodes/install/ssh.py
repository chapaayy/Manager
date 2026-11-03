"""SSH transport and read-only preflight for first node bootstrap."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import socket
import time

import paramiko

from ...xray import Endpoint

SSH_TIMEOUT = 16
FP = re.compile(r"SHA256:[A-Za-z0-9+/]{42,44}\Z")

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

RESUME_PROBE = (
    "set -eu; test \"$(id -u)\" = 0; "
    "test -s /opt/remnanode/domain; test -s /opt/remnanode/node.env; "
    "test -s /opt/remnanode/docker-compose.yml; test -s /opt/nginx/docker-compose.yml; "
    "domain=\"$(cat /opt/remnanode/domain)\"; "
    "case \"$domain\" in *[!a-zA-Z0-9.-]*|'') exit 65;; esac; "
    "test -s \"/opt/nginx/certs/${domain}_fullchain.pem\"; "
    "test -s \"/opt/nginx/certs/${domain}_privkey.key\"; "
    "test \"$(docker inspect -f '{{.State.Running}}' remnanode)\" = true; "
    "test \"$(docker inspect -f '{{.State.Running}}' nginx)\" = true; "
    "printf 'DOMAIN=%s\\n' \"$domain\""
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
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def ssh_open(ip: str, port: int, password: str, expected_fp: str | None = None):
    ip = check_ip(ip)
    if not 1 <= port <= 65535:
        raise ValueError("Неверный SSH-порт")
    if not 1 <= len(password) <= 512 or "\x00" in password:
        raise ValueError("Неверный SSH-пароль")
    sock = socket.create_connection((ip, port), timeout=SSH_TIMEOUT)
    connection = paramiko.Transport(
        sock, disabled_algorithms={"pubkeys": ["ssh-rsa"]}
    )
    try:
        connection.banner_timeout = SSH_TIMEOUT
        connection.auth_timeout = SSH_TIMEOUT
        connection.start_client(timeout=SSH_TIMEOUT)
        actual = fingerprint(connection.get_remote_server_key())
        if expected_fp is not None and actual != expected_fp:
            raise ValueError(
                "SSH-ключ изменился. Установка остановлена: сверь fingerprint в панели провайдера."
            )
        connection.auth_password("root", password, fallback=False)
        if not connection.is_authenticated():
            raise ValueError("SSH root авторизация не удалась")
        return connection, actual
    except Exception:
        connection.close()
        raise


def run_command(
    connection, command: str, *, timeout: int = 30, max_bytes: int = 16000
) -> str:
    channel = connection.open_session(timeout=SSH_TIMEOUT)
    channel.settimeout(min(timeout, 120))
    try:
        channel.exec_command(command)
        chunks = []
        total = 0
        deadline = time.monotonic() + timeout
        while (
            not channel.exit_status_ready()
            or channel.recv_ready()
            or channel.recv_stderr_ready()
        ):
            if time.monotonic() > deadline:
                raise TimeoutError("SSH-команда выполняется слишком долго")
            for ready, recv in (
                (channel.recv_ready, channel.recv),
                (channel.recv_stderr_ready, channel.recv_stderr),
            ):
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
            raise RuntimeError(f"Удалённая операция завершилась с кодом {rc}")
        return b"".join(chunks).decode(errors="replace")
    finally:
        channel.close()


def preflight(
    ip: str,
    port: int,
    password: str,
    domain: str,
    expected_fp: str | None = None,
) -> dict:
    check_ip(ip)
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}", domain)
        or len(domain) > 253
    ):
        raise ValueError("Укажи корректный домен VPS")
    try:
        ips = {
            item[4][0]
            for item in socket.getaddrinfo(
                domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        }
    except OSError:
        raise ValueError("Домен VPS не имеет A-записи") from None
    if ip not in ips or len(ips) != 1:
        raise ValueError(
            "A-запись домена должна однозначно указывать на IP этого VPS"
        )

    connection, actual = ssh_open(ip, port, password, expected_fp)
    try:
        output = run_command(connection, READONLY)
    finally:
        connection.close()

    lines = output.splitlines()
    allowed = {"OS", "VERSION", "UID", "ARCH", "DISK", "NGINX_DIR", "NODE_DIR"}
    data = dict(
        line.split("=", 1)
        for line in lines
        if "=" in line and line.split("=", 1)[0] in allowed
    )
    ports = (
        "\n".join(lines[lines.index("PORTS_BEGIN") + 1 :])
        if "PORTS_BEGIN" in lines
        else ""
    )
    occupied = sorted(
        value
        for value in (80, 443, 2222)
        if re.search(rf"(?<!\d):{value}\s", ports)
    )
    warnings = []
    if data.get("OS") not in ("ubuntu", "debian"):
        warnings.append("Поддерживаются только чистые Ubuntu и Debian")
    if data.get("UID") != "0":
        warnings.append("Первичная установка требует root")
    if data.get("ARCH") not in ("x86_64", "aarch64"):
        warnings.append("Текущая архитектура не поддерживается")
    if int(data.get("DISK", "0") or 0) < 2500:
        warnings.append("На диске требуется минимум 2,5 ГБ свободного места")
    if data.get("NGINX_DIR") == "yes" or data.get("NODE_DIR") == "yes":
        warnings.append(
            "На VPS обнаружена прежняя установка Nginx/Remnawave; перезапись запрещена"
        )
    if not ports.strip():
        warnings.append("Не удалось получить список занятых портов")
    if occupied:
        warnings.append("Порты заняты: " + ", ".join(map(str, occupied)))
    return {
        "fingerprint": actual,
        "os": data.get("OS", "?"),
        "version": data.get("VERSION", "?"),
        "architecture": data.get("ARCH", "?"),
        "free_disk_mb": int(data.get("DISK", "0") or 0),
        "busy_ports": occupied,
        "warnings": warnings,
        "ready": not warnings,
        "read_only": True,
    }


def verify_existing_install(connection, source: Endpoint):
    try:
        result = run_command(
            connection, RESUME_PROBE, timeout=30, max_bytes=1000
        )
    except (RuntimeError, TimeoutError, ValueError):
        raise ValueError(
            "На VPS не подтверждены Nginx, Remnawave Node и TLS. "
            "Автоматическое продолжение без проверки запрещено."
        ) from None
    if result.strip() != "DOMAIN=" + source.domain:
        raise ValueError(
            "Домен установленной VPS не совпадает с сохранённой нодой"
        )
