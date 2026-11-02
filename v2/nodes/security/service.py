"""Queue validated desired security state for the privileged node helper."""
from __future__ import annotations

import copy
import ipaddress

from ... import agent_transport, storage
from .repository import get, set_last_job


def _panel_ipv4() -> str:
    raw = str(
        storage.get_panel().get("outbound_ip", "")
    ).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError(
            "Для защиты Node API укажи публичный IPv4 Remnawave Panel в настройках"
        ) from None
    if address.version != 4 or not address.is_global:
        raise ValueError(
            "Для защиты Node API нужен публичный IPv4 Remnawave Panel"
        )
    return str(address)


def queue_apply(node_id: str, expected_revision: int) -> dict:
    state = get(node_id)
    if (
        not isinstance(expected_revision, int)
        or expected_revision < 1
    ):
        raise ValueError("Сначала сохрани профиль сети и защиты")
    if state["revision"] != expected_revision:
        raise ValueError(
            "Профиль изменился после подтверждения. "
            "Обнови страницу и проверь настройки."
        )

    config = copy.deepcopy(state["config"])
    panel_ip = ""
    if config["firewall"]["enabled"]:
        panel_ip = _panel_ipv4()

    allowed = list(
        config["firewall"]["extra_allowed_sources"]
    )
    if panel_ip:
        panel_cidr = panel_ip + "/32"
        if panel_cidr not in allowed:
            allowed.insert(0, panel_cidr)

    config["firewall"]["allowed_sources"] = allowed
    config["firewall"]["panel_ip"] = panel_ip
    job = agent_transport.enqueue(
        node_id,
        "security.settings.apply",
        {
            "revision": state["revision"],
            "config": config,
        },
        ttl=900,
        internal=True,
    )
    set_last_job(node_id, job["id"], state["revision"])
    return {**job, "revision": state["revision"]}
