"""Pinned HTTPS client for the single configured Remnawave panel."""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit

from ...repositories import panel as panel_repository
from .errors import PanelError


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname: str, ip: str):
        super().__init__(
            hostname, 443, context=ssl.create_default_context(), timeout=12
        )
        self._ip = ip

    def connect(self):
        raw = socket.create_connection((self._ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise PanelError(
            "Нужен публичный HTTPS-домен Remnawave без путей и параметров"
        )
    if "." not in parsed.hostname:
        raise PanelError("Нужен публичный домен Remnawave")
    return f"https://{parsed.hostname.lower()}"


def _safe_panel_error_text(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > 220 or any(c in value for c in "\r\n\x00"):
        return ""
    if re.search(
        r"(?i)-----BEGIN|-----END|authorization\s*:|bearer\s+|"
        r"(?:token|secret|password|private[_-]?key)\s*[:=]",
        value,
    ):
        return ""
    if re.search(r"[A-Za-z0-9+/_=-]{48,}", value):
        return ""
    return value


def _panel_error_details(raw: bytes) -> str:
    if not raw or len(raw) > 8192:
        return ""
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""

    pieces = []
    code = _safe_panel_error_text(payload.get("errorCode"))
    if code and re.fullmatch(r"[A-Za-z0-9_-]{1,24}", code):
        pieces.append("код " + code)

    messages = payload.get("message")
    if isinstance(messages, str):
        messages = [messages]
    if isinstance(messages, list):
        for value in messages[:2]:
            message = _safe_panel_error_text(value)
            if message and message not in pieces:
                pieces.append(message)

    errors = payload.get("errors")
    if isinstance(errors, list):
        for issue in errors[:3]:
            if isinstance(issue, str):
                detail = _safe_panel_error_text(issue)
            elif isinstance(issue, dict):
                field = _safe_panel_error_text(
                    issue.get("property") or issue.get("field") or issue.get("path")
                )
                detail = _safe_panel_error_text(issue.get("message"))
                if not detail and isinstance(issue.get("constraints"), dict):
                    for value in issue["constraints"].values():
                        detail = _safe_panel_error_text(value)
                        if detail:
                            break
                detail = (
                    field + ": " + detail
                    if field and detail
                    else (detail or field)
                )
            else:
                continue
            if detail and detail not in pieces:
                pieces.append(detail)
    return (" — " + "; ".join(pieces))[:350] if pieces else ""


def guard_node_only_tls_paths(config: dict) -> None:
    if not isinstance(config, dict):
        raise PanelError("Неверный Xray Config Profile")
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        stream = inbound.get("streamSettings", {})
        tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
        certificates = (
            tls.get("certificates", []) if isinstance(tls, dict) else []
        )
        for cert in certificates:
            if not isinstance(cert, dict):
                continue
            # Legacy inline PEM may exist only while an explicit migration is
            # being inspected/rolled back. New Manager profiles use paths.
            if "key" in cert or "certificate" in cert:
                continue
            for field in ("keyFile", "certificateFile"):
                path = cert.get(field)
                if not isinstance(path, str) or not path.startswith(
                    "/opt/nginx/certs/"
                ):
                    raise PanelError(
                        "Для новых нод допускаются только пути сертификатов на VPS"
                    )


def _permitted(method: str, path: str, body: dict | None) -> bool:
    allowed = method == "GET" and body is None and (
        path in ("/api/config-profiles", "/api/keygen", "/api/nodes")
        or re.fullmatch(
            r"/api/config-profiles/[a-fA-F0-9-]{36}(?:/inbounds)?", path
        )
    )
    allowed = allowed or (
        method == "POST"
        and path in ("/api/config-profiles", "/api/nodes")
        and isinstance(body, dict)
    )
    allowed = allowed or (
        method == "PATCH"
        and path == "/api/config-profiles"
        and isinstance(body, dict)
        and set(body) == {"uuid", "config"}
        and isinstance(body.get("config"), dict)
        and isinstance(body.get("uuid"), str)
        and re.fullmatch(r"[a-fA-F0-9-]{36}", body["uuid"]) is not None
    )
    allowed = allowed or (
        method == "POST"
        and body == {"forceRestart": True}
        and re.fullmatch(
            r"/api/nodes/[a-fA-F0-9-]{36}/actions/restart", path
        )
        is not None
    )
    allowed = allowed or (
        method == "DELETE"
        and body is None
        and re.fullmatch(
            r"/api/(?:nodes|config-profiles)/[a-fA-F0-9-]{36}", path
        )
        is not None
    )
    return bool(allowed)


def request(method: str, path: str, body: dict | None = None):
    if not _permitted(method, path, body):
        raise PanelError("Запрещённый API-маршрут")
    if (
        body is not None
        and method in ("POST", "PATCH")
        and path == "/api/config-profiles"
    ):
        guard_node_only_tls_paths(body.get("config", {}))

    panel = panel_repository.get_panel()
    token = panel_repository.get_panel_token().strip()
    caddy_key = panel_repository.get_caddy_api_key().strip()
    if not panel["url"] or not token:
        raise PanelError("Сначала укажи домен и API-токен Remnawave")
    if any(c in value for value in (token, caddy_key) for c in ("\r", "\n")):
        raise PanelError("Токен содержит недопустимые символы переноса строки")

    host = urlsplit(validate_url(panel["url"])).hostname
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [item[4][0] for item in addresses]
        if not ips or any(
            not ipaddress.ip_address(ip).is_global for ip in ips
        ):
            raise PanelError("DNS панели должен указывать только на публичные IP")
    except OSError:
        raise PanelError("Не удалось получить DNS-запись Remnawave") from None

    connection = PinnedHTTPS(host, ips[0])
    try:
        headers = {
            "Authorization": (
                token if token.lower().startswith("bearer ") else "Bearer " + token
            ),
            "Accept": "application/json",
        }
        if caddy_key:
            headers["X-Api-Key"] = caddy_key

        encoded = None
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode()
            if len(encoded) > 180000:
                raise PanelError("Конфигурация слишком большая")
            headers["Content-Type"] = "application/json"

        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        if response.status == 401:
            raise PanelError(
                f"HTTP 401 на {path}: доступ к API отклонён. Проверь API-токен "
                "в Remnawave Settings → API Tokens. Если панель защищена Caddy/MFA, "
                "укажи отдельный X-Api-Key портала в дополнительных настройках."
            )
        if response.status in (301, 302, 303, 307, 308):
            raise PanelError(
                f"HTTP {response.status} на {path}: API перенаправлен, вероятно, "
                "на страницу входа. Для Caddy/MFA нужен ключ портала."
            )
        if response.status == 403:
            raise PanelError(
                f"HTTP 403 на {path}: токен или защита прокси не разрешают запрос."
            )
        if not 200 <= response.status < 300:
            error_detail = _panel_error_details(response.read(8193))
            raise PanelError(
                f"Remnawave вернула HTTP {response.status} на {path}{error_detail}"
            )

        raw = response.read(300001)
        if len(raw) > 300000:
            raise PanelError("Слишком большой ответ API")
        if not raw and response.status == 204 and (
            method == "DELETE" or path.endswith("/actions/restart")
        ):
            return {"response": {}}
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise PanelError("Неожиданный формат JSON")
        return payload
    except (
        OSError,
        ssl.SSLError,
        http.client.HTTPException,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        raise PanelError("Не удалось безопасно подключиться к Remnawave") from None
    finally:
        connection.close()
