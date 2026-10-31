"""Read-only Remnawave adapter for one configured panel.

All allowed routes are static. HTTPS DNS is checked and pinned to avoid SSRF/
DNS rebinding; credentials never go to the frontend or node agents.
"""
import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit
from . import storage


class PanelError(ValueError):
    pass


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname: str, ip: str):
        super().__init__(hostname, 443, context=ssl.create_default_context(), timeout=12)
        self._ip = ip

    def connect(self):
        raw = socket.create_connection((self._ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def validate_url(url: str) -> str:
    u = urlsplit(url)
    if (u.scheme != "https" or not u.hostname or u.username or u.password
            or u.port not in (None, 443) or u.path not in ("", "/") or u.query or u.fragment):
        raise PanelError("Нужен публичный HTTPS-домен Remnawave без путей и параметров")
    if "." not in u.hostname:
        raise PanelError("Нужен публичный домен Remnawave")
    return f"https://{u.hostname.lower()}"


def _safe_panel_error_text(value) -> str:
    """Allow only short, single-line diagnostic text; never echo submitted secrets."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > 220 or any(c in value for c in "\r\n\x00"):
        return ""
    if re.search(r"(?i)-----BEGIN|-----END|authorization\s*:|bearer\s+|(?:token|secret|password|private[_-]?key)\s*[:=]", value):
        return ""
    if re.search(r"[A-Za-z0-9+/_=-]{48,}", value):
        return ""
    return value


def _panel_error_details(raw: bytes) -> str:
    """Summarize documented Remnawave errors without logging raw responses or PEM."""
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
                field = _safe_panel_error_text(issue.get("property") or issue.get("field") or issue.get("path"))
                detail = _safe_panel_error_text(issue.get("message"))
                if not detail and isinstance(issue.get("constraints"), dict):
                    for value in issue["constraints"].values():
                        detail = _safe_panel_error_text(value)
                        if detail:
                            break
                detail = (field + ": " + detail) if field and detail else (detail or field)
            else:
                continue
            if detail and detail not in pieces:
                pieces.append(detail)
    return (" — " + "; ".join(pieces))[:350] if pieces else ""


def guard_node_only_tls_paths(config: dict) -> None:
    """Reject embedded PEM in Manager-owned Remnawave profiles.

    Remnawave Backend's resolveCertificate() returns the original file paths
    when Panel cannot read them, allowing the Node's Xray to read mounted
    local files. Never send or persist a private key through Panel API.
    """
    if not isinstance(config,dict):
        raise PanelError("Неверный Xray Config Profile")
    for inbound in config.get("inbounds",[]):
        if not isinstance(inbound,dict):
            continue
        stream=inbound.get("streamSettings",{})
        tls=stream.get("tlsSettings",{}) if isinstance(stream,dict) else {}
        for cert in tls.get("certificates",[]) if isinstance(tls,dict) else []:
            if not isinstance(cert,dict):
                continue
            if "key" in cert or "certificate" in cert:
                # Legacy profiles may contain inline PEM during explicit
                # migration rollback; caller must use raw trusted API path
                # only for its own validated profile. New profiles have paths.
                continue
            for field in ("keyFile","certificateFile"):
                path=cert.get(field)
                if not isinstance(path,str) or not path.startswith("/opt/nginx/certs/"):
                    raise PanelError("Для новых нод допускаются только пути сертификатов на VPS")


def request(method: str, path: str, body: dict | None = None):
    permitted = (method == "GET" and body is None and (
        path in ("/api/config-profiles", "/api/keygen", "/api/nodes") or
        re.fullmatch(r"/api/config-profiles/[a-fA-F0-9-]{36}(?:/inbounds)?", path)
    )) or (method == "POST" and path in ("/api/config-profiles", "/api/nodes") and isinstance(body, dict))
    permitted = permitted or (method == "PATCH" and path == "/api/config-profiles"
        and isinstance(body,dict) and set(body)=={"uuid","config"}
        and isinstance(body.get("config"),dict)
        and isinstance(body.get("uuid"),str)
        and re.fullmatch(r"[a-fA-F0-9-]{36}",body["uuid"]) is not None)
    permitted = permitted or (method == "POST" and body == {"forceRestart":True}
        and re.fullmatch(r"/api/nodes/[a-fA-F0-9-]{36}/actions/restart", path) is not None)
    permitted = permitted or (method == "DELETE" and body is None and
        re.fullmatch(r"/api/(?:nodes|config-profiles)/[a-fA-F0-9-]{36}",path) is not None)
    if not permitted:
        raise PanelError("Запрещённый API-маршрут")
    if body is not None and method in ("POST","PATCH") and path=="/api/config-profiles":
        guard_node_only_tls_paths(body.get("config",{}))
    panel = storage.get_panel()
    token = storage.get_panel_token().strip()
    caddy_key = storage.get_caddy_api_key().strip()
    if not panel["url"] or not token:
        raise PanelError("Сначала укажи домен и API-токен Remnawave")
    if any(c in value for value in (token, caddy_key) for c in ("\\r", "\\n")):
        raise PanelError("Токен содержит недопустимые символы переноса строки")
    host = urlsplit(validate_url(panel["url"])).hostname
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [i[4][0] for i in addresses]
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise PanelError("DNS панели должен указывать только на публичные IP")
    except OSError:
        raise PanelError("Не удалось получить DNS-запись Remnawave") from None
    connection = PinnedHTTPS(host, ips[0])
    try:
        headers = {
            "Authorization": token if token.lower().startswith("bearer ") else "Bearer " + token,
            "Accept": "application/json",
        }
        # Optional second factor issued by a Caddy Auth Portal in front of Remnawave.
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
            raise PanelError(f"HTTP 403 на {path}: токен или защита прокси не разрешают запрос.")
        if not 200 <= response.status < 300:
            error_detail = _panel_error_details(response.read(8193))
            raise PanelError(f"Remnawave вернула HTTP {response.status} на {path}{error_detail}")
        body = response.read(300001)
        if len(body) > 300000:
            raise PanelError("Слишком большой ответ API")
        if not body and response.status == 204 and (method == "DELETE" or path.endswith("/actions/restart")):
            return {"response":{}}
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise PanelError("Неожиданный формат JSON")
        return payload
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError):
        raise PanelError("Не удалось безопасно подключиться к Remnawave") from None
    finally:
        connection.close()


def list_profiles() -> list[dict]:
    response = request("GET", "/api/config-profiles").get("response", {})
    rows = response.get("configProfiles", []) if isinstance(response, dict) else []
    if not isinstance(rows, list):
        raise PanelError("Некорректный список Config Profiles")
    result = []
    for p in rows[:200]:
        if not isinstance(p, dict) or not isinstance(p.get("uuid"), str):
            continue
        raw = p.get("inbounds")
        if not isinstance(raw, list) or not raw:
            extra = request("GET", f"/api/config-profiles/{p['uuid']}/inbounds").get("response", {})
            raw = extra.get("inbounds", []) if isinstance(extra, dict) else []
        result.append({
            "uuid": p["uuid"], "name": str(p.get("name", ""))[:100],
            "inbounds": [{"uuid": i["uuid"], "tag": str(i.get("tag", ""))[:100]}
                         for i in raw if isinstance(i, dict) and isinstance(i.get("uuid"), str)]
        })
    return result


def validate_profile_selection(profile: str, inbounds: list[str]) -> None:
    profiles = list_profiles()
    chosen = next((p for p in profiles if p["uuid"] == profile), None)
    if not chosen:
        raise PanelError("Профиль не найден в основной Remnawave")
    permitted = {i["uuid"] for i in chosen["inbounds"]}
    if not inbounds or len(set(inbounds)) != len(inbounds) or not set(inbounds) <= permitted:
        raise PanelError("Выбранные inbound-ы не принадлежат профилю")


def panel_status() -> dict:
    profiles = list_profiles()
    key_response = request("GET", "/api/keygen").get("response", {})
    key_exists = isinstance(key_response, dict) and bool(
        key_response.get("secretKey") or key_response.get("pubKey")
    )
    return {"connected": True, "config_profiles": profiles, "node_key_available": key_exists}



def node_secret() -> str:
    """The panel-issued base64 SECRET_KEY is never exposed in browser responses."""
    response = request("GET", "/api/keygen").get("response")
    if not isinstance(response, dict):
        raise PanelError("API /api/keygen: неизвестный формат ответа")
    secret = response.get("secretKey") or response.get("pubKey")
    if not isinstance(secret, str) or not 16 <= len(secret) <= 32768:
        raise PanelError("API /api/keygen не вернул подходящий ключ Remnawave Node")
    if not re.fullmatch(r"[a-zA-Z0-9+/=_-]+", secret):
        raise PanelError("Ключ Remnawave Node содержит недопустимые символы")
    return secret


def create_profile(name: str, xray_config: dict) -> dict:
    """Create a dedicated profile, never rewrite a profile used by other VPS."""
    if not 3 <= len(name) <= 70 or not re.fullmatch(r"[A-Za-z0-9_ -]+", name):
        raise PanelError("Название профиля: только латинские буквы, цифры, пробел, _ и -")
    response = request("POST", "/api/config-profiles", {"name": name, "config": xray_config})
    data = response.get("response")
    if not isinstance(data, dict) or not isinstance(data.get("uuid"), str):
        raise PanelError("Remnawave не вернула UUID профиля после создания")
    created = data["uuid"]
    result = next((p for p in list_profiles() if p["uuid"] == created), None)
    if not result:
        raise PanelError("Профиль создан, но не найден при повторной проверке — проверь Remnawave")
    return result


def register_node(name: str, address: str, country: str,
                  profile_uuid: str, inbound_uuids: list[str]) -> str:
    if not 3 <= len(name) <= 30 or any(ord(c) < 32 for c in name):
        raise PanelError("Имя ноды Remnawave должно содержать 3–30 символов")
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise PanelError("Неверный код страны")
    if not inbound_uuids or len(set(inbound_uuids)) != len(inbound_uuids):
        raise PanelError("Нет подтверждённых inbound-ов для ноды")
    rows = request("GET", "/api/nodes").get("response")
    if not isinstance(rows, list):
        raise PanelError("Неожиданный формат списка нод")
    if any(isinstance(n,dict) and (n.get("name")==name or n.get("address")==address) for n in rows):
        raise PanelError("Нода уже зарегистрирована в Remnawave — повторное создание отменено")
    payload = {
        "name": name, "address": address, "port": 2222, "countryCode": country,
        "isTrafficTrackingActive": False, "consumptionMultiplier": 1,
        "configProfile": {
            "activeConfigProfileUuid": profile_uuid, "activeInbounds": inbound_uuids
        }
    }
    created = request("POST", "/api/nodes", payload).get("response")
    if not isinstance(created,dict) or not isinstance(created.get("uuid"),str):
        raise PanelError("Remnawave не подтвердила создание ноды")
    return created["uuid"]



def node_health(node_uuid: str) -> dict:
    """Inspect panel telemetry; only an explicit active connection is accepted."""
    rows = request("GET", "/api/nodes").get("response")
    if not isinstance(rows, list):
        raise PanelError("Не удалось получить состояния нод")
    row = next((n for n in rows if isinstance(n, dict) and n.get("uuid")==node_uuid), None)
    if row is None:
        raise PanelError("Remnawave ещё не показывает новую ноду в списке")
    connected = row.get("isConnected")
    if connected is None:
        connected = row.get("is_connected")
    # Do not infer readiness from presence alone.
    version = row.get("xrayVersion")
    versions = row.get("versions")
    if not version and isinstance(versions, dict):
        version = versions.get("xray")
    uptime = row.get("xrayUptime")
    return {"connected": connected is True,
            "xray_running": bool(version) or (isinstance(uptime,(int,float)) and uptime>0),
            "xray_version": str(version or "")[:50]}

def detailed_profile(uuid: str) -> dict:
    """Full Xray profile, restricted to an already-known UUID."""
    if not re.fullmatch(r"[a-fA-F0-9-]{36}",uuid):
        raise PanelError("Неверный UUID Xray-профиля")
    data=request("GET",f"/api/config-profiles/{uuid}").get("response")
    if not isinstance(data,dict) or not isinstance(data.get("config"),dict):
        raise PanelError("Remnawave не вернула полный Xray-профиль")
    return data


def replace_profile_config(uuid: str, config: dict):
    if not isinstance(config,dict) or not isinstance(config.get("inbounds"),list):
        raise PanelError("Нельзя отправить неполный Xray-конфиг")
    return request("PATCH","/api/config-profiles",{"uuid":uuid,"config":config})


def restart_node(uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}",uuid):
        raise PanelError("Неверный UUID ноды")
    return request("POST",f"/api/nodes/{uuid}/actions/restart",{"forceRestart":True})



def delete_node(uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}",uuid):
        raise PanelError("Недопустимый UUID удаляемой ноды")
    return request("DELETE",f"/api/nodes/{uuid}")


def delete_profile(uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}",uuid):
        raise PanelError("Недопустимый UUID Xray-профиля")
    return request("DELETE",f"/api/config-profiles/{uuid}")
