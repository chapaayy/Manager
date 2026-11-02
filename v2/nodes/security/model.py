"""Pure validation and normalization for node security profiles."""
from __future__ import annotations

import copy
import ipaddress

DEFAULT_CONFIG = {
    "tcp": {
        "enabled": True,
        "congestion_control": "bbr",
        "qdisc": "fq",
    },
    "fail2ban": {
        "enabled": True,
        "maxretry": 6,
        "findtime_seconds": 600,
        "bantime_seconds": 3600,
        "trusted_sources": [],
    },
    "firewall": {
        "enabled": True,
        "extra_allowed_sources": [],
        "block_ipv6": True,
    },
    "logs": {
        "nginx": {
            "enabled": True,
            "size_mb": 20,
            "archives": 7,
            "compress": True,
        },
        "remnanode": {
            "enabled": True,
            "size_mb": 50,
            "archives": 5,
            "compress": True,
        },
    },
}

TCP_CC = {"bbr", "cubic", "reno"}
QDISC = {"fq", "fq_codel"}


def _boolean(value, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(field + " должен быть включён или выключен")
    return value


def _integer(
    value,
    field: str,
    minimum: int,
    maximum: int,
    *,
    allow_minus_one: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(field + " должен быть целым числом")
    if allow_minus_one and value == -1:
        return value
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{field}: допустимо от {minimum} до {maximum}"
        )
    return value


def _sources(value, field: str, *, limit: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(field + ": слишком много адресов")
    result = []
    seen = set()
    for raw in value:
        if not isinstance(raw, str) or len(raw) > 80:
            raise ValueError(field + ": неверный IP/CIDR")
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError:
            raise ValueError(
                field + ": неверный IP/CIDR " + raw[:40]
            ) from None
        canonical = str(network)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _log_profile(value, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(name + ": неверные настройки")
    return {
        "enabled": _boolean(value.get("enabled"), name + ".enabled"),
        "size_mb": _integer(
            value.get("size_mb"), name + ".size_mb", 1, 2048
        ),
        "archives": _integer(
            value.get("archives"), name + ".archives", 1, 30
        ),
        "compress": _boolean(
            value.get("compress"), name + ".compress"
        ),
    }


def normalize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError(
            "Настройки безопасности должны быть объектом"
        )
    tcp = raw.get("tcp")
    fail2ban = raw.get("fail2ban")
    firewall = raw.get("firewall")
    logs = raw.get("logs")
    if not all(
        isinstance(item, dict)
        for item in (tcp, fail2ban, firewall, logs)
    ):
        raise ValueError("Неполный профиль сети и защиты")

    cc = str(tcp.get("congestion_control", "")).strip().lower()
    qdisc = str(tcp.get("qdisc", "")).strip().lower()
    if cc not in TCP_CC:
        raise ValueError(
            "TCP congestion control должен быть bbr, cubic или reno"
        )
    if qdisc not in QDISC:
        raise ValueError("QDisc должен быть fq или fq_codel")

    return {
        "tcp": {
            "enabled": _boolean(tcp.get("enabled"), "tcp.enabled"),
            "congestion_control": cc,
            "qdisc": qdisc,
        },
        "fail2ban": {
            "enabled": _boolean(
                fail2ban.get("enabled"), "fail2ban.enabled"
            ),
            "maxretry": _integer(
                fail2ban.get("maxretry"),
                "Fail2Ban попытки",
                1,
                20,
            ),
            "findtime_seconds": _integer(
                fail2ban.get("findtime_seconds"),
                "Fail2Ban окно",
                60,
                86400,
            ),
            "bantime_seconds": _integer(
                fail2ban.get("bantime_seconds"),
                "Fail2Ban бан",
                60,
                604800,
                allow_minus_one=True,
            ),
            "trusted_sources": _sources(
                fail2ban.get("trusted_sources", []),
                "Fail2Ban доверенные адреса",
            ),
        },
        "firewall": {
            "enabled": _boolean(
                firewall.get("enabled"), "firewall.enabled"
            ),
            "extra_allowed_sources": _sources(
                firewall.get("extra_allowed_sources", []),
                "Firewall разрешённые адреса",
            ),
            "block_ipv6": _boolean(
                firewall.get("block_ipv6"),
                "firewall.block_ipv6",
            ),
        },
        "logs": {
            "nginx": _log_profile(
                logs.get("nginx"), "Nginx logrotate"
            ),
            "remnanode": _log_profile(
                logs.get("remnanode"), "Remnawave logrotate"
            ),
        },
    }


def default_config() -> dict:
    return copy.deepcopy(DEFAULT_CONFIG)
