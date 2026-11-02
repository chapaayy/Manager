"""Render allowlisted node artifacts and the dedicated Xray profile."""
from __future__ import annotations

from pathlib import Path

from ... import preset_deploy
from ...template_engine import Endpoint, new_inbound, validate_rendered
from .ssh import check_ip

DATA = Path(__file__).resolve().parents[2] / "data"


def config_profile_name(source: Endpoint, mode: str = "direct") -> str:
    return (
        f"XPPN {source.code} {source.country} BRIDGE VLESS TLS"
        if mode == "bridge"
        else f"XPPN {source.code} {source.country} VLESS TLS"
    )


def xray_config(source: Endpoint) -> dict:
    inbound = new_inbound(source.code + "_VLESS_TLS_IN", 443, source.domain)
    config = {
        "log": {
            "error": "/var/log/remnanode/error.log",
            "access": "/var/log/remnanode/access.log",
            "loglevel": "warning",
        },
        "inbounds": [inbound],
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom"},
            {"tag": "BLOCKED", "protocol": "blackhole"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "BLOCKED"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "BLOCKED"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCKED"},
                {"type": "field", "inboundTag": [inbound["tag"]], "outboundTag": "DIRECT"},
            ],
            "domainStrategy": "IPIfNonMatch",
        },
    }
    validate_rendered(config)
    return config


def preview_plan(
    source: Endpoint, preset_id: str | None = None, role: str = "regular"
) -> dict:
    if preset_id is not None:
        snapshot = preset_deploy.render_snapshot(preset_id, source, role)
        return {
            "name": config_profile_name(source, snapshot["mode"]),
            "xray": snapshot["xray"],
            "nginx": snapshot["nginx"],
            "preset_name": snapshot["preset_name"],
            "preset_mode": snapshot["mode"],
            "revisions": snapshot["revisions"],
            "note": snapshot["note"],
            "files": [
                "/opt/nginx/nginx.conf",
                "/opt/nginx/docker-compose.yml",
                "/opt/remnanode/docker-compose.yml",
                "/opt/remnanode/node.env",
                f"/opt/nginx/certs/{source.domain}_fullchain.pem",
                f"/opt/nginx/certs/{source.domain}_privkey.key",
            ],
            "variables": [
                {"key": "source.code", "value": source.code},
                {"key": "source.domain", "value": source.domain},
                {"key": "deployment.mode", "value": snapshot["mode"]},
            ],
        }

    tag = source.code + "_VLESS_TLS_IN"
    proposed = xray_config(source)
    return {
        "name": config_profile_name(source),
        "xray": proposed,
        "tls_profile_mode": "node_local_paths",
        "tls_node_files": "/opt/nginx/certs/",
        "nginx": (DATA / "nginx.conf")
        .read_text(encoding="utf-8")
        .replace("{{source.domain}}", source.domain),
        "files": [
            "/opt/nginx/nginx.conf",
            "/opt/nginx/docker-compose.yml",
            f"/opt/nginx/certs/{source.domain}_fullchain.pem",
            f"/opt/nginx/certs/{source.domain}_privkey.key",
            "/opt/remnanode/docker-compose.yml",
            "/opt/remnanode/node.env",
        ],
        "variables": [
            {"key": "source.code", "value": source.code},
            {"key": "source.domain", "value": source.domain},
            {"key": "inbound.tag", "value": tag},
            {
                "key": "tls.certificate",
                "value": "Certbot только на ноде; профиль хранит keyFile/certificateFile",
            },
        ],
        "note": (
            "Приватный ключ выпускается и хранится на VPS ноды. В отдельном "
            "Xray-профиле Remnawave только пути keyFile/certificateFile. Панель "
            "не меняем, volumes туда не добавляем; при недоступном пути на панели "
            "Remnawave сохраняет файловые ссылки для Xray ноды."
        ),
    }


def render_files(
    source: Endpoint,
    secret_key: str,
    panel_ip: str,
    snapshot: dict | None = None,
) -> dict:
    if "\n" in secret_key or "\r" in secret_key:
        raise ValueError("Ключ Remnawave содержит недопустимые символы")
    panel_ip = check_ip(panel_ip)
    template = (
        snapshot["nginx"]
        if snapshot
        else (DATA / "nginx.conf").read_text(encoding="utf8")
    )
    nginx = template.replace("{{source.domain}}", source.domain)
    if "{{" in nginx:
        raise ValueError("В nginx.conf остались неразрешённые переменные")
    html_site = (
        '<!doctype html><html lang="ru"><meta charset="utf-8">'
        "<title>Welcome</title><body><h1>Service online</h1></body></html>\n"
    )
    return {
        "domain": source.domain + "\n",
        "panel-ip": panel_ip + "\n",
        "nginx.conf": nginx,
        "nginx-compose.yml": (
            snapshot["nginx_compose"]
            if snapshot
            else (DATA / "nginx-compose.yml").read_text(encoding="utf8")
        ),
        "remnanode-compose.yml": (
            snapshot["node_compose"]
            if snapshot
            else (DATA / "remnanode-compose.yml").read_text(encoding="utf8")
        ),
        "node.env": "SECRET_KEY=" + secret_key + "\n",
        "index.html": html_site,
        "remote-install.sh": (DATA / "remote-install.sh").read_text(encoding="utf8"),
        "node-baseline.sh": (DATA / "node-baseline.sh").read_text(encoding="utf8"),
    }
