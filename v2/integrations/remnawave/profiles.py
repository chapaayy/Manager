"""Remnawave Config Profile operations."""
from __future__ import annotations

import re

from .errors import PanelError


def list_profiles(request) -> list[dict]:
    response = request("GET", "/api/config-profiles").get("response", {})
    rows = response.get("configProfiles", []) if isinstance(response, dict) else []
    if not isinstance(rows, list):
        raise PanelError("Некорректный список Config Profiles")

    result = []
    for profile in rows[:200]:
        if not isinstance(profile, dict) or not isinstance(
            profile.get("uuid"), str
        ):
            continue
        raw = profile.get("inbounds")
        if not isinstance(raw, list) or not raw:
            extra = request(
                "GET", f"/api/config-profiles/{profile['uuid']}/inbounds"
            ).get("response", {})
            raw = extra.get("inbounds", []) if isinstance(extra, dict) else []
        result.append(
            {
                "uuid": profile["uuid"],
                "name": str(profile.get("name", ""))[:100],
                "inbounds": [
                    {
                        "uuid": inbound["uuid"],
                        "tag": str(inbound.get("tag", ""))[:100],
                    }
                    for inbound in raw
                    if isinstance(inbound, dict)
                    and isinstance(inbound.get("uuid"), str)
                ],
            }
        )
    return result


def validate_profile_selection(list_profiles_fn, profile: str, inbounds: list[str]) -> None:
    profiles = list_profiles_fn()
    chosen = next((item for item in profiles if item["uuid"] == profile), None)
    if not chosen:
        raise PanelError("Профиль не найден в основной Remnawave")
    permitted = {item["uuid"] for item in chosen["inbounds"]}
    if (
        not inbounds
        or len(set(inbounds)) != len(inbounds)
        or not set(inbounds) <= permitted
    ):
        raise PanelError("Выбранные inbound-ы не принадлежат профилю")


def create_profile(request, list_profiles_fn, name: str, xray_config: dict) -> dict:
    if not 3 <= len(name) <= 70 or not re.fullmatch(
        r"[A-Za-z0-9_ -]+", name
    ):
        raise PanelError(
            "Название профиля: только латинские буквы, цифры, пробел, _ и -"
        )
    response = request(
        "POST", "/api/config-profiles", {"name": name, "config": xray_config}
    )
    data = response.get("response")
    if not isinstance(data, dict) or not isinstance(data.get("uuid"), str):
        raise PanelError("Remnawave не вернула UUID профиля после создания")
    created = data["uuid"]
    result = next(
        (item for item in list_profiles_fn() if item["uuid"] == created), None
    )
    if not result:
        raise PanelError(
            "Профиль создан, но не найден при повторной проверке — проверь Remnawave"
        )
    return result


def detailed_profile(request, uuid: str) -> dict:
    if not re.fullmatch(r"[a-fA-F0-9-]{36}", uuid):
        raise PanelError("Неверный UUID Xray-профиля")
    data = request("GET", f"/api/config-profiles/{uuid}").get("response")
    if not isinstance(data, dict) or not isinstance(data.get("config"), dict):
        raise PanelError("Remnawave не вернула полный Xray-профиль")
    return data


def replace_profile_config(request, uuid: str, config: dict):
    if not isinstance(config, dict) or not isinstance(
        config.get("inbounds"), list
    ):
        raise PanelError("Нельзя отправить неполный Xray-конфиг")
    return request(
        "PATCH", "/api/config-profiles", {"uuid": uuid, "config": config}
    )


def delete_profile(request, uuid: str):
    if not re.fullmatch(r"[a-fA-F0-9-]{36}", uuid):
        raise PanelError("Недопустимый UUID Xray-профиля")
    return request("DELETE", f"/api/config-profiles/{uuid}")
