"""Shared Remnawave profile-assignment rules for one Manager-owned node."""
from __future__ import annotations

from ..template_engine import Endpoint
from .install.render import config_profile_name


class ProfileOwnershipError(ValueError):
    pass


def attached_profile(row: dict) -> tuple[str | None, bool]:
    profile = row.get("configProfile")
    if isinstance(profile, dict) and "activeConfigProfileUuid" in profile:
        value = profile["activeConfigProfileUuid"]
        if value is None or value == "":
            return None, True
        if isinstance(value, str):
            return value, True
        raise ProfileOwnershipError(
            "Remnawave вернула некорректную привязку профиля"
        )

    for key in ("configProfileUuid", "activeConfigProfileUuid"):
        if key not in row:
            continue
        value = row[key]
        if value is None or value == "":
            return None, True
        if isinstance(value, str):
            return value, True
        raise ProfileOwnershipError(
            "Remnawave вернула некорректный UUID профиля"
        )

    if "configProfile" in row and profile is None:
        return None, True
    return None, False


def expected_profile_name(node: dict) -> str:
    mode = "bridge" if node.get("role") == "entry" else "direct"
    return config_profile_name(
        Endpoint(node["code"], node["domain"], node["country"]),
        mode,
    )


def profile_users(
    rows: list[dict], profile_uuid: str, remote_uuid: str = ""
) -> list[dict]:
    if not isinstance(rows, list):
        raise ProfileOwnershipError("Список нод Remnawave недоступен")
    others = []
    for row in rows:
        if not isinstance(row, dict):
            raise ProfileOwnershipError("Неверный ответ Remnawave")
        attached, known = attached_profile(row)
        if not known:
            raise ProfileOwnershipError(
                "Нельзя проверить привязки всех нод к профилям Remnawave"
            )
        if attached == profile_uuid and row.get("uuid") != remote_uuid:
            uid = row.get("uuid")
            if not isinstance(uid, str) or not uid:
                raise ProfileOwnershipError(
                    "У другой ноды нет UUID. Удаление общего профиля запрещено"
                )
            others.append(
                {
                    "uuid": uid,
                    "name": str(row.get("name") or uid)[:100],
                }
            )
    return sorted(others, key=lambda item: item["uuid"])


def assert_target_assignment(
    rows: list[dict], remote_uuid: str, profile_uuid: str
) -> bool:
    if not isinstance(rows, list):
        raise ProfileOwnershipError("Список нод Remnawave недоступен")
    found = False
    for row in rows:
        if not isinstance(row, dict):
            raise ProfileOwnershipError("Неверный ответ Remnawave")
        attached, known = attached_profile(row)
        if not known:
            raise ProfileOwnershipError(
                "Неизвестны привязки других Xray-профилей"
            )
        if row.get("uuid") == remote_uuid:
            found = True
            if attached != profile_uuid:
                raise ProfileOwnershipError(
                    "У ноды изменился активный Xray-профиль"
                )
        elif attached == profile_uuid:
            raise ProfileOwnershipError(
                "Xray-профиль используется другой нодой"
            )
    return found


def assert_unshared(rows: list[dict], profile_uuid: str) -> None:
    if not isinstance(rows, list):
        raise ProfileOwnershipError(
            "Не удалось проверить использование Xray-профиля"
        )
    for row in rows:
        if not isinstance(row, dict):
            raise ProfileOwnershipError("Неправильный ответ Remnawave")
        attached, known = attached_profile(row)
        if not known:
            raise ProfileOwnershipError("Привязки профилей неизвестны")
        if attached == profile_uuid:
            raise ProfileOwnershipError("Профиль ещё используется нодой")
