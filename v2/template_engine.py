"""XPPN 2.0: deterministic, validated Xray bridge rendering.

No API calls, files, shell, or deployment here. A generated configuration is a
PROPOSAL until explicitly applied by a future verified deployment adapter.
"""
from __future__ import annotations

import copy
import difflib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from typing import Sequence

CODE = re.compile(r"^[A-Z][A-Z0-9_-]{1,19}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
PORTS_RESERVED = {443, 8443}
EXTRA_PORT_START = 8444
EXTRA_PORT_END = 8999


class TemplateError(ValueError):
    pass


@dataclass(frozen=True)
class Endpoint:
    code: str
    domain: str
    country: str

    def __post_init__(self):
        if not CODE.fullmatch(self.code):
            raise TemplateError("Код сервера: 2–20 латинских заглавных букв, цифр, _ или -")
        if not DOMAIN.fullmatch(self.domain) or self.domain.endswith("."):
            raise TemplateError("Нужен корректный домен сервера (не URL и не IP)")
        try:
            ipaddress.ip_address(self.domain)
        except ValueError:
            pass
        else:
            raise TemplateError("Укажи домен, а не IP")
        if not re.fullmatch(r"[A-Z]{2}", self.country):
            raise TemplateError("Код страны должен состоять из двух букв, например DE")


@dataclass(frozen=True)
class Exit:
    endpoint: Endpoint
    user_id: str
    port: int = 443
    inbound_port: int | None = None

    def __post_init__(self):
        try:
            ident = uuid.UUID(self.user_id)
        except (TypeError, ValueError, AttributeError):
            raise TemplateError("Межсерверный UUID недействителен") from None
        if str(ident) != self.user_id.lower():
            raise TemplateError("UUID должен быть в обычном формате с дефисами")
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise TemplateError("Некорректный исходящий TCP-порт")
        if self.inbound_port is not None and (
            not isinstance(self.inbound_port, int) or not EXTRA_PORT_START <= self.inbound_port <= EXTRA_PORT_END
        ):
            raise TemplateError("Дополнительный inbound должен использовать порт 8444–8999")


def new_inbound(tag: str, port: int, domain: str) -> dict:
    return {
        "tag": tag, "port": port, "listen": "0.0.0.0", "protocol": "vless",
        "settings": {
            "clients": [],
            "fallbacks": [{"dest": "127.0.0.1:8080"}],
            "decryption": "none",
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "raw", "security": "tls",
            "tlsSettings": {
                "alpn": ["http/1.1"],
                "certificates": [{
                    "keyFile": f"/opt/nginx/certs/{domain}_privkey.key",
                    "certificateFile": f"/opt/nginx/certs/{domain}_fullchain.pem",
                }],
                "rejectUnknownSni": True,
            },
        },
    }


def new_outbound(exit_node: Exit) -> dict:
    e = exit_node.endpoint
    return {
        "tag": f"TO_{e.code}_VLESS_TLS_OUT",
        "protocol": "vless",
        "settings": {"vnext": [{
            "port": exit_node.port,
            "users": [{
                "id": exit_node.user_id,
                "flow": "xtls-rprx-vision",
                "encryption": "none",
            }],
            "address": e.domain,
        }]},
        "streamSettings": {
            "network": "raw", "security": "tls",
            "tlsSettings": {
                "alpn": ["http/1.1"],
                "serverName": e.domain, "fingerprint": "firefox", "allowInsecure": False,
            },
        },
    }


def _route(outbound: str, inbound: str | None = None, **conditions) -> dict:
    result = {"type": "field"}
    result.update(conditions)
    if inbound:
        result["inboundTag"] = [inbound]
    result["outboundTag"] = outbound
    return result


def allocate_port(used: set[int]) -> int:
    for port in range(EXTRA_PORT_START, EXTRA_PORT_END + 1):
        if port not in used:
            return port
    raise TemplateError("Нет свободных портов для новых входных подключений")


def render_bridge(source: Endpoint, exits: Sequence[Exit], *, default_exit: str | None = None) -> dict:
    """Render original RUS1 filtering/routing semantics plus one dedicated inbound per extra exit.

    The first exit uses TCP/443 (main), TCP/8443 (filtered). Additional exits get
    their own TCP ports. Never interpret extra exits as automatic balancing.
    """
    if not exits:
        raise TemplateError("У моста должен быть хотя бы один выходной сервер")
    if len(exits) > 100:
        raise TemplateError("Слишком много выходных серверов")
    codes = [e.endpoint.code for e in exits]
    if len(set(codes)) != len(codes) or source.code in codes:
        raise TemplateError("Названия нод в мосте должны быть уникальны")
    if default_exit and default_exit not in codes:
        raise TemplateError("Главная выходная нода не найдена")
    first = next((x for x in exits if x.endpoint.code == default_exit), exits[0])
    remaining = [x for x in exits if x.endpoint.code != first.endpoint.code]
    main_tag = f"{source.code}_{first.endpoint.code}_VLESS_TLS_IN"
    filter_tag = f"{source.code}_FILTER_VLESS_TLS_IN"
    config = {
        "log": {
            "error": "/var/log/remnanode/error.log",
            "access": "/var/log/remnanode/access.log",
            "loglevel": "warning",
        },
        "inbounds": [
            new_inbound(main_tag, 443, source.domain),
            new_inbound(filter_tag, 8443, source.domain),
        ],
        "outbounds": [new_outbound(e) for e in exits]
        + [{"tag": "DIRECT", "protocol": "freedom"},
           {"tag": "BLOCKED", "protocol": "blackhole"}],
        "routing": {
            "rules": [
                _route("BLOCKED", ip=["geoip:private"]),
                _route("BLOCKED", domain=["geosite:private"]),
                _route("BLOCKED", protocol=["bittorrent"]),
                _route(f"TO_{first.endpoint.code}_VLESS_TLS_OUT", filter_tag, domain=["geosite:youtube"]),
                _route("DIRECT", filter_tag, ip=["geoip:ru"]),
                _route("DIRECT", filter_tag, domain=["geosite:category-ru"]),
                _route(f"TO_{first.endpoint.code}_VLESS_TLS_OUT", filter_tag),
                _route(f"TO_{first.endpoint.code}_VLESS_TLS_OUT", main_tag),
            ],
            "domainStrategy": "IPIfNonMatch",
        },
    }
    ports = set(PORTS_RESERVED)
    for exit_node in remaining:
        port = exit_node.inbound_port if exit_node.inbound_port is not None else allocate_port(ports)
        if port in ports:
            raise TemplateError(f"Порт inbound {port} уже занят другим маршрутом")
        ports.add(port)
        tag = f"{source.code}_{exit_node.endpoint.code}_VLESS_TLS_IN"
        config["inbounds"].append(new_inbound(tag, port, source.domain))
        config["routing"]["rules"].append(
            _route(f"TO_{exit_node.endpoint.code}_VLESS_TLS_OUT", tag)
        )
    validate_rendered(config)
    return config


def validate_rendered(config: dict) -> None:
    """Check internal Xray references and deterministic output, NOT a replacement for xray run -test."""
    if not isinstance(config, dict):
        raise TemplateError("Конфигурация должна быть JSON-объектом")
    ins = config.get("inbounds", [])
    outs = config.get("outbounds", [])
    if not ins or not outs:
        raise TemplateError("Отсутствуют inbounds/outbounds")
    inbound_tags = [i.get("tag") for i in ins]
    outbound_tags = [o.get("tag") for o in outs]
    ports = [i.get("port") for i in ins]
    if len(set(inbound_tags)) != len(inbound_tags) or len(set(outbound_tags)) != len(outbound_tags):
        raise TemplateError("В конфиге повторяются теги")
    if len(set(ports)) != len(ports):
        raise TemplateError("Два inbound используют один и тот же порт")
    valid_in = set(inbound_tags)
    valid_out = set(outbound_tags)
    for rule in config.get("routing", {}).get("rules", []):
        if rule.get("outboundTag") not in valid_out:
            raise TemplateError(f"Routing ссылается на несуществующий outbound: {rule.get('outboundTag')}")
        if any(tag not in valid_in for tag in rule.get("inboundTag", [])):
            raise TemplateError("Routing ссылается на несуществующий inbound")
    encoded = json.dumps(config, ensure_ascii=False)
    if "{{" in encoded or "}}" in encoded:
        raise TemplateError("В итоговом конфиге остались незаполненные переменные")


def diff_configs(current: dict | None, proposed: dict) -> str:
    before = json.dumps(current or {}, indent=2, ensure_ascii=False, sort_keys=False).splitlines()
    after = json.dumps(proposed, indent=2, ensure_ascii=False, sort_keys=False).splitlines()
    return "\n".join(difflib.unified_diff(before, after, fromfile="текущий.json", tofile="предлагаемый.json", lineterm=""))


def safe_preview(config: dict) -> dict:
    """Never expose real bridge user UUIDs through preview or logs."""
    redacted = copy.deepcopy(config)
    for item in redacted.get("outbounds", []):
        for vnext in item.get("settings", {}).get("vnext", []):
            for user in vnext.get("users", []):
                if "id" in user:
                    user["id"] = "<скрыто>"
    return redacted


def variables_map(source: Endpoint, exits: Sequence[Exit]) -> list[dict]:
    values = [
        ("source.code", "Название входной ноды", source.code),
        ("source.domain", "Домен и пути TLS-сертификатов", source.domain),
    ]
    for index, e in enumerate(exits):
        values.extend([
            (f"exits.{index}.code", "Код выходной ноды", e.endpoint.code),
            (f"exits.{index}.domain", "Адрес выхода и TLS SNI", e.endpoint.domain),
            (f"exits.{index}.uuid", "UUID межсерверного подключения", "<скрыто>"),
        ])
    return [{"key": key, "description": desc, "preview": value} for key, desc, value in values]



def extend_existing_bridge(current: dict, source: Endpoint, new_exit: Exit) -> dict:
    """Preserve EVERY existing Xray field and add only one outbound, inbound and routing rule.

    No balancing, no changes to current inbound clients, filters, fallbacks,
    routing rules, TLS certificates, users or existing exits.
    """
    validate_rendered(current)
    new_tag = f"TO_{new_exit.endpoint.code}_VLESS_TLS_OUT"
    if any(o.get("tag") == new_tag for o in current["outbounds"]):
        raise TemplateError("Этот выход уже присутствует в текущей конфигурации")
    if any(
        new_exit.endpoint.domain == v.get("address")
        for o in current["outbounds"]
        for group in o.get("settings", {}).get("vnext", [])
        for v in [group]
    ):
        raise TemplateError("Выход с этим доменом уже добавлен")
    inbound_tag = f"{source.code}_{new_exit.endpoint.code}_VLESS_TLS_IN"
    if any(i.get("tag") == inbound_tag for i in current["inbounds"]):
        raise TemplateError("Входной тег уже существует")
    base = next((i for i in current["inbounds"]
                 if i.get("port") == 443 and i.get("protocol") == "vless"
                 and i.get("streamSettings", {}).get("security") == "tls"
                 and i.get("streamSettings", {}).get("network") == "raw"), None)
    if not base:
        raise TemplateError("Нет образцового VLESS TLS RAW inbound на порту 443. Требуется отдельный шаблон.")
    used = {i.get("port") for i in current["inbounds"]}
    desired = new_exit.inbound_port
    if desired is not None and desired in used:
        raise TemplateError(f"Порт {desired} уже используется")
    port = desired or allocate_port(used)
    proposed = copy.deepcopy(current)
    new_input = copy.deepcopy(base)
    new_input["tag"] = inbound_tag
    new_input["port"] = port
    proposed["inbounds"].append(new_input)
    proposed["outbounds"].append(new_outbound(new_exit))
    proposed["routing"]["rules"].append(_route(new_tag, inbound_tag))
    validate_rendered(proposed)
    return proposed
