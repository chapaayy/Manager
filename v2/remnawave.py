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


def request(method: str, path: str, body: dict | None = None):
    permitted = (method == "GET" and body is None and (
        path in ("/api/config-profiles", "/api/keygen", "/api/nodes") or
        re.fullmatch(r"/api/config-profiles/[a-fA-F0-9-]{36}/inbounds", path)
    )) or (method == "POST" and path in ("/api/config-profiles", "/api/nodes") and isinstance(body, dict))
    if not permitted:
        raise PanelError("Запрещённый API-маршрут")
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
            raise PanelError(f"Remnawave вернула HTTP {response.status} на {path}")
        body = response.read(300001)
        if len(body) > 300000:
            raise PanelError("Слишком большой ответ API")
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
    if not 3 <= len(name) <= 70 or any(ord(c) < 32 for c in name):
        raise PanelError("Некорректное название профиля")
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
