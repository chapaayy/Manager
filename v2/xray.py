"""Shared Xray primitives used by active Direct-node workflows.

This module deliberately contains no Bridge topology, persistence or HTTP
behavior. It validates deterministic Xray structures and node-local TLS paths.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

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
    def has_placeholder(value):
        if isinstance(value, str):
            return re.search(r"\{\{[A-Za-z0-9.*_-]+\}\}", value) is not None
        if isinstance(value, dict):
            return any(has_placeholder(v) for v in value.values())
        if isinstance(value, list):
            return any(has_placeholder(v) for v in value)
        return False
    if has_placeholder(config):
        raise TemplateError("В итоговом конфиге остались незаполненные переменные")

