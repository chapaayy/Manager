"""Remnawave Node operations."""
from __future__ import annotations

import re

from .errors import PanelError


def node_secret(request) -> str:
    response = request("GET", "/api/keygen").get("response")
    if not isinstance(response, dict):
        raise PanelError("API /api/keygen: неизвестный формат ответа")
    secret = response.get("secretKey") or response.get("pubKey")
    if not isinstance(secret, str) or not 16 <= len(secret) <= 32768:
        raise PanelError(
            "API /api/keygen не вернул подходящий ключ Remnawave Node"
        )
    if not re.fullmatch(r"[a-zA-Z0-9+/=_-]+", secret):
        raise PanelError(
            "Ключ Remnawave Node содержит недопустимые символы"
        )
    return secret


def register_node(
    request,
    name: str,
    address: str,
    country: str,
    profile_uuid: str,
    inbound_uuids: list[str],
) -> str:
    if not 3 <= len(name) <= 30 or any(ord(c) < 32 for c in name):
        raise PanelError("Имя ноды Remnawave должно содержать 3–30 символов")
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise PanelError("Неверный код страны")
    if not inbound_uuids or len(set(inbound_uuids)) != len(inbound_uuids):
        raise PanelError("Нет подтверждённых inbound-ов для ноды")

    rows = request("GET", "/api/nodes").get("response")
    if not isinstance(rows, list):
        raise PanelError("Неожиданный формат списка нод")
    if any(
        isinstance(node, dict)
        and (node.get("name") == name or node.get("address") == address)
        for node in rows
    ):
        raise PanelError(
            "Нода уже зарегистрирована в Remnawave — повторное создание отменено"
        )

    payload = {
        "name": name,
        "address": address,
        "port": 2222,
        "countryCode": country,
        "isTrafficTrackingActive": False,
        "consumptionMultiplier": 1,
        "configProfile": {
            "activeConfigProfileUuid": profile_uuid,
            "activeInbounds": inbound_uuids,
        },
    }
    created = request("POST", "/api/nodes", payload).get("response")
    if not isinstance(created, dict) or not isinstance(
        created.get("uuid"), str
    ):
        raise PanelError("Remnawave не подтвердила создание ноды")
    return created["uuid"]


def node_health(request, node_uuid: str) -> dict:
    rows = request("GET", "/api/nodes").get("response")
    if not isinstance(rows, list):
        raise PanelError("Не удалось получить состояния нод")
    row = next(
        (
            node
            for node in rows
            if isinstance(node, dict) and node.get("uuid") == node_uuid
        ),
        None,
    )
    if row is None:
        raise PanelError("Remnawave ещё не показывает новую ноду в списке")

    connected = row.get("isConnected")
    if connected is None:
        connected = row.get("is_connected")
    version = row.get("xrayVersion")
    versions = row.get("versions")
    if not version and isinstance(versions, dict):
        version = versions.get("xray")
    uptime = row.get("xrayUptime")
    return {
        "connected": connected is True,
        "xray_running": bool(version)
        or (isinstance(uptime, (int, float)) and uptime > 0),
        "xray_version": str(version or "")[:50],
    }


def restart_node(request, uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}", uuid):
        raise PanelError("Неверный UUID ноды")
    return request(
        "POST",
        f"/api/nodes/{uuid}/actions/restart",
        {"forceRestart": True},
    )


def delete_node(request, uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}", uuid):
        raise PanelError("Недопустимый UUID удаляемой ноды")
    return request("DELETE", f"/api/nodes/{uuid}")
