"""Ownership and shape checks for Manager-owned Remnawave TLS profiles."""
from __future__ import annotations

import re

from ... import remnawave
from ...xray import Endpoint
from ..install.render import config_profile_name
from ..profile_ownership import (
    ProfileOwnershipError,
    attached_profile as _attached_profile,
)
from .errors import CertificateSyncError, LocalTLSError


def paths(domain: str) -> dict:
    return {
        "keyFile": f"/opt/nginx/certs/{domain}_privkey.key",
        "certificateFile": f"/opt/nginx/certs/{domain}_fullchain.pem",
    }


def attached_profile(row: dict) -> tuple[str | None, bool]:
    try:
        return _attached_profile(row)
    except ProfileOwnershipError as exc:
        raise CertificateSyncError(str(exc)) from None


def api_error(exc: Exception) -> str:
    match = re.search(r"(?<!\d)HTTP\s+([45]\d\d)\b", str(exc))
    return " (HTTP " + match.group(1) + ")" if match else ""


def owned_profile(node: dict, job: dict) -> dict:
    try:
        rows = remnawave.request("GET", "/api/nodes").get("response")
    except remnawave.PanelError as exc:
        raise CertificateSyncError(
            "Не удалось получить список нод через Remnawave API"
            + api_error(exc)
        ) from None
    if not isinstance(rows, list):
        raise CertificateSyncError(
            "Remnawave вернула неправильный формат списка нод"
        )

    own = False
    for row in rows:
        if not isinstance(row, dict):
            raise CertificateSyncError(
                "Некорректный ответ Remnawave о нодах"
            )
        attached, known = attached_profile(row)
        if not known:
            raise CertificateSyncError(
                "Remnawave не вернула привязки профилей для проверки безопасности"
            )
        if row.get("uuid") == job["remote_uuid"]:
            own = True
            if attached != job["profile_uuid"]:
                raise CertificateSyncError(
                    "У ноды изменился активный Xray-профиль"
                )
        elif attached == job["profile_uuid"]:
            raise CertificateSyncError(
                "Xray-профиль используется другой нодой, изменение запрещено"
            )
    if not own:
        raise CertificateSyncError("Нода не найдена в Remnawave API")

    try:
        data = remnawave.detailed_profile(job["profile_uuid"])
    except remnawave.PanelError as exc:
        raise CertificateSyncError(
            "Не удалось прочитать Xray-профиль через API" + api_error(exc)
        ) from None

    expected = config_profile_name(
        Endpoint(node["code"], node["domain"], node["country"])
    )
    if data.get("name") != expected:
        raise CertificateSyncError(
            "Имя Xray-профиля отличается от созданного менеджером"
        )
    return data


def certificate_slot(node: dict, job: dict):
    try:
        profile = owned_profile(node, job)
        config = profile["config"]
        inbounds = [
            item
            for item in config.get("inbounds", [])
            if isinstance(item, dict)
            and item.get("tag") == node["code"] + "_VLESS_TLS_IN"
        ]
        if len(inbounds) != 1:
            raise LocalTLSError("TLS inbound не найден или неоднозначен")
        tls = inbounds[0].get("streamSettings", {}).get("tlsSettings", {})
        certificates = tls.get("certificates")
        if (
            not isinstance(certificates, list)
            or len(certificates) != 1
            or not isinstance(certificates[0], dict)
        ):
            raise LocalTLSError(
                "TLS профиль нестандартный; изменение запрещено"
            )
        return profile, certificates
    except CertificateSyncError as exc:
        raise LocalTLSError(str(exc)) from None
    except (KeyError, TypeError, AttributeError):
        raise LocalTLSError(
            "Remnawave вернула нестандартный профиль"
        ) from None
