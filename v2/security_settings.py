"""Structured per-node network/security settings.

The Manager stores desired state, while the privileged node helper is the only
component allowed to mutate the VPS. No shell snippets or arbitrary paths are
accepted from the browser.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import time

from . import agent_transport, storage

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
        "nginx": {"enabled": True, "size_mb": 20, "archives": 7, "compress": True},
        "remnanode": {"enabled": True, "size_mb": 50, "archives": 5, "compress": True},
    },
}

TCP_CC = {"bbr", "cubic", "reno"}
QDISC = {"fq", "fq_codel"}


def initialize() -> None:
    with storage.connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS node_security_settings(
          node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
          config_json TEXT NOT NULL,
          revision INTEGER NOT NULL DEFAULT 1,
          applied_revision INTEGER NOT NULL DEFAULT 0,
          last_job_id TEXT NOT NULL DEFAULT '',
          updated_at INTEGER NOT NULL DEFAULT 0,
          applied_at INTEGER NOT NULL DEFAULT 0
        );
        """)


def _boolean(value, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(field + " должен быть включён или выключен")
    return value


def _integer(value, field: str, minimum: int, maximum: int, *, allow_minus_one: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(field + " должен быть целым числом")
    if allow_minus_one and value == -1:
        return value
    if not minimum <= value <= maximum:
        raise ValueError(f"{field}: допустимо от {minimum} до {maximum}")
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
            raise ValueError(field + ": неверный IP/CIDR " + raw[:40]) from None
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
        "size_mb": _integer(value.get("size_mb"), name + ".size_mb", 1, 2048),
        "archives": _integer(value.get("archives"), name + ".archives", 1, 30),
        "compress": _boolean(value.get("compress"), name + ".compress"),
    }


def normalize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Настройки безопасности должны быть объектом")
    tcp = raw.get("tcp")
    f2b = raw.get("fail2ban")
    firewall = raw.get("firewall")
    logs = raw.get("logs")
    if not all(isinstance(x, dict) for x in (tcp, f2b, firewall, logs)):
        raise ValueError("Неполный профиль сети и защиты")

    cc = str(tcp.get("congestion_control", "")).strip().lower()
    qdisc = str(tcp.get("qdisc", "")).strip().lower()
    if cc not in TCP_CC:
        raise ValueError("TCP congestion control должен быть bbr, cubic или reno")
    if qdisc not in QDISC:
        raise ValueError("QDisc должен быть fq или fq_codel")

    return {
        "tcp": {
            "enabled": _boolean(tcp.get("enabled"), "tcp.enabled"),
            "congestion_control": cc,
            "qdisc": qdisc,
        },
        "fail2ban": {
            "enabled": _boolean(f2b.get("enabled"), "fail2ban.enabled"),
            "maxretry": _integer(f2b.get("maxretry"), "Fail2Ban попытки", 1, 20),
            "findtime_seconds": _integer(
                f2b.get("findtime_seconds"), "Fail2Ban окно", 60, 86400),
            "bantime_seconds": _integer(
                f2b.get("bantime_seconds"), "Fail2Ban бан", 60, 604800,
                allow_minus_one=True),
            "trusted_sources": _sources(
                f2b.get("trusted_sources", []), "Fail2Ban доверенные адреса"),
        },
        "firewall": {
            "enabled": _boolean(firewall.get("enabled"), "firewall.enabled"),
            "extra_allowed_sources": _sources(
                firewall.get("extra_allowed_sources", []),
                "Firewall разрешённые адреса"),
            "block_ipv6": _boolean(firewall.get("block_ipv6"), "firewall.block_ipv6"),
        },
        "logs": {
            "nginx": _log_profile(logs.get("nginx"), "Nginx logrotate"),
            "remnanode": _log_profile(logs.get("remnanode"), "Remnawave logrotate"),
        },
    }


def default_config() -> dict:
    return copy.deepcopy(DEFAULT_CONFIG)


def get(node_id: str) -> dict:
    storage.get_node(node_id)
    initialize()
    with storage.connect() as db:
        row = db.execute(
            """SELECT config_json,revision,applied_revision,last_job_id,updated_at,applied_at
               FROM node_security_settings WHERE node_id=?""", (node_id,)).fetchone()
    if not row:
        return {
            "node_id": node_id,
            "config": default_config(),
            "revision": 0,
            "applied_revision": 0,
            "last_job_id": "",
            "updated_at": 0,
            "applied_at": 0,
            "changed_since_apply": True,
        }
    try:
        config = normalize(json.loads(row["config_json"]))
    except (ValueError, json.JSONDecodeError):
        config = default_config()
    return {
        "node_id": node_id,
        "config": config,
        "revision": int(row["revision"]),
        "applied_revision": int(row["applied_revision"]),
        "last_job_id": row["last_job_id"],
        "updated_at": int(row["updated_at"]),
        "applied_at": int(row["applied_at"]),
        "changed_since_apply": int(row["revision"]) != int(row["applied_revision"]),
    }


def save(node_id: str, config: dict, expected_revision: int) -> dict:
    storage.get_node(node_id)
    normalized = normalize(config)
    if not isinstance(expected_revision, int) or expected_revision < 0:
        raise ValueError("Некорректная ревизия настроек")
    initialize()
    now = int(time.time())
    encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
    with storage.transaction() as db:
        row = db.execute(
            "SELECT revision FROM node_security_settings WHERE node_id=?",
            (node_id,)).fetchone()
        if row is None:
            if expected_revision != 0:
                raise ValueError("Настройки уже изменились. Обнови страницу.")
            revision = 1
            db.execute(
                """INSERT INTO node_security_settings
                   (node_id,config_json,revision,updated_at)
                   VALUES(?,?,?,?)""",
                (node_id, encoded, revision, now))
        else:
            if int(row["revision"]) != expected_revision:
                raise ValueError("Настройки уже изменились. Обнови страницу.")
            revision = expected_revision + 1
            db.execute(
                """UPDATE node_security_settings
                   SET config_json=?,revision=?,updated_at=? WHERE node_id=?""",
                (encoded, revision, now, node_id))
        storage.event(db, "node.security.settings", node_id,
                      f"Security settings revision {revision}")
    return get(node_id)


def _panel_ipv4() -> str:
    raw = str(storage.get_panel().get("outbound_ip", "")).strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError("Для защиты Node API укажи публичный IPv4 Remnawave Panel в настройках") from None
    if ip.version != 4 or not ip.is_global:
        raise ValueError("Для защиты Node API нужен публичный IPv4 Remnawave Panel")
    return str(ip)


def queue_apply(node_id: str) -> dict:
    state = get(node_id)
    if state["revision"] == 0:
        state = save(node_id, state["config"], 0)
    config = copy.deepcopy(state["config"])
    panel_ip = ""
    if config["firewall"]["enabled"]:
        panel_ip = _panel_ipv4()
    allowed = list(config["firewall"]["extra_allowed_sources"])
    if panel_ip:
        panel_cidr = panel_ip + "/32"
        if panel_cidr not in allowed:
            allowed.insert(0, panel_cidr)
    config["firewall"]["allowed_sources"] = allowed
    config["firewall"]["panel_ip"] = panel_ip
    job = agent_transport.enqueue(
        node_id, "security.settings.apply",
        {"revision": state["revision"], "config": config},
        ttl=900, internal=True)
    with storage.transaction() as db:
        db.execute(
            "UPDATE node_security_settings SET last_job_id=? WHERE node_id=?",
            (job["id"], node_id))
        storage.event(db, "node.security.apply", node_id,
                      f"Queued security revision {state['revision']}")
    return {**job, "revision": state["revision"]}


def mark_applied(node_id: str, result: dict) -> None:
    revision = result.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        return
    now = int(time.time())
    initialize()
    with storage.transaction() as db:
        row = db.execute(
            "SELECT revision FROM node_security_settings WHERE node_id=?",
            (node_id,)).fetchone()
        if not row:
            return
        db.execute(
            """UPDATE node_security_settings SET applied_revision=?,applied_at=?
               WHERE node_id=?""", (revision, now, node_id))
        storage.event(db, "node.security.applied", node_id,
                      f"Applied security revision {revision}")
