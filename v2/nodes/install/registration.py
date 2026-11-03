"""Remnawave registration phase for an already prepared VPS."""
from __future__ import annotations

import time

from ... import remnawave, storage
from ...xray import Endpoint
from .render import config_profile_name, xray_config


def complete_panel_registration(node_id: str, source: Endpoint):
    snapshot = storage.get_install_preset(node_id)
    mode = snapshot["mode"] if snapshot else "direct"
    name = config_profile_name(source, mode)
    expected_tags = (
        snapshot["inbound_tags"]
        if snapshot
        else [source.code + "_VLESS_TLS_IN"]
    )
    installation = storage.get_install_job(node_id)
    profiles = remnawave.list_profiles()
    saved_uuid = installation["profile_uuid"]

    if saved_uuid:
        profile = next(
            (item for item in profiles if item["uuid"] == saved_uuid), None
        )
        if profile is None:
            raise ValueError(
                "Ранее созданный Xray-профиль не найден в панели. Проверь его вручную."
            )
    else:
        if any(item["name"] == name for item in profiles):
            raise ValueError(
                "В Remnawave уже существует профиль с таким именем. "
                "Проверь его вручную, чтобы избежать дубликатов."
            )
        storage.set_install_status(
            node_id, "installing", "Создаём отдельный Xray Config Profile"
        )
        profile = remnawave.create_profile(
            name, snapshot["xray"] if snapshot else xray_config(source)
        )
        storage.set_install_status(
            node_id,
            "installing",
            "Профиль создан, готовим регистрацию ноды",
            profile_uuid=profile["uuid"],
        )

    matched = {
        item.get("tag"): item.get("uuid") for item in profile["inbounds"]
    }
    selected = [matched[tag] for tag in expected_tags if tag in matched]
    if (
        len(selected) != len(expected_tags)
        or len(set(selected)) != len(expected_tags)
    ):
        raise ValueError(
            "Remnawave не подтвердила все inbound выбранного пресета"
        )

    storage.set_install_status(
        node_id, "installing", "Регистрируем ноду в Remnawave"
    )
    remote_id = remnawave.register_node(
        source.code,
        source.domain,
        source.country,
        profile["uuid"],
        selected,
    )
    storage.set_install_status(
        node_id,
        "registered",
        "Нода зарегистрирована, ожидается подтверждение её связи с Remnawave",
        remote_uuid=remote_id,
        profile_uuid=profile["uuid"],
    )

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            health = remnawave.node_health(remote_id)
            if health["connected"] and health["xray_running"]:
                storage.set_install_status(
                    node_id,
                    "ready",
                    "Remnawave подтвердила подключение и работу Xray ("
                    + (health["xray_version"] or "активен")
                    + "). Для клиентского доступа настрой Hosts и Internal Squads.",
                )
                from ..tls import queue_initial_check

                queue_initial_check(node_id)
                break
        except remnawave.PanelError:
            pass
        time.sleep(3)
