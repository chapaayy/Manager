"""Compose validated TCP, Fail2Ban, firewall and log settings."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from .common import (
    bootstrap_ssh_peer,
    fail,
    replace_root_file,
    security_bool,
    security_int,
    security_networks,
)
from .security_fail2ban import apply_fail2ban_settings
from .security_firewall import apply_firewall_settings
from .security_logs import apply_log_settings
from .security_tcp import apply_tcp_settings

BOOTSTRAP_PEER = Path("/var/lib/node-manager/bootstrap-ssh-peer")


def _validate(cfg: dict) -> str:
    if not isinstance(cfg, dict):
        fail("invalid security config")
    for name in ("tcp", "fail2ban", "firewall", "logs"):
        if not isinstance(cfg.get(name), dict):
            fail("incomplete security config")

    firewall_cfg = cfg["firewall"]
    panel_ip = str(firewall_cfg.get("panel_ip", "")).strip()

    security_bool(cfg["tcp"].get("enabled"), "tcp.enabled")
    if str(cfg["tcp"].get("congestion_control", "")).lower() not in {
        "bbr",
        "cubic",
        "reno",
    }:
        fail("unsupported congestion control")
    if str(cfg["tcp"].get("qdisc", "")).lower() not in {
        "fq",
        "fq_codel",
    }:
        fail("unsupported qdisc")

    security_bool(
        cfg["fail2ban"].get("enabled"), "fail2ban.enabled"
    )
    security_int(
        cfg["fail2ban"].get("maxretry"),
        "fail2ban.maxretry",
        1,
        20,
    )
    security_int(
        cfg["fail2ban"].get("findtime_seconds"),
        "fail2ban.findtime",
        60,
        86400,
    )
    security_int(
        cfg["fail2ban"].get("bantime_seconds"),
        "fail2ban.bantime",
        60,
        604800,
        True,
    )
    security_networks(
        cfg["fail2ban"].get("trusted_sources", []),
        "fail2ban.trusted",
    )

    security_bool(
        firewall_cfg.get("enabled"), "firewall.enabled"
    )
    security_bool(
        firewall_cfg.get("block_ipv6"), "firewall.block_ipv6"
    )
    security_networks(
        firewall_cfg.get("allowed_sources", []),
        "firewall.allowed",
    )

    for logname in ("nginx", "remnanode"):
        item = cfg["logs"].get(logname)
        if not isinstance(item, dict):
            fail("logs incomplete")
        security_bool(
            item.get("enabled"), logname + ".enabled"
        )
        security_int(
            item.get("size_mb"), logname + ".size", 1, 2048
        )
        security_int(
            item.get("archives"),
            logname + ".archives",
            1,
            30,
        )
        security_bool(
            item.get("compress"), logname + ".compress"
        )
    return panel_ip


def _apply(cfg: dict):
    panel_ip = _validate(cfg)
    logs = apply_log_settings(cfg["logs"])
    fail2ban = apply_fail2ban_settings(
        cfg["fail2ban"], panel_ip
    )
    tcp = apply_tcp_settings(cfg["tcp"])
    firewall = apply_firewall_settings(cfg["firewall"])
    return {
        "tcp": tcp,
        "fail2ban": fail2ban,
        "firewall": firewall,
        "logs": logs,
    }


def apply_security_settings(data):
    revision = data.get("revision")
    cfg = data.get("config")
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
    ):
        fail("invalid security revision")
    result = _apply(cfg)
    if BOOTSTRAP_PEER.is_symlink():
        fail("bootstrap peer marker linked")
    try:
        BOOTSTRAP_PEER.unlink()
    except FileNotFoundError:
        pass
    return {
        "revision": revision,
        "applied": True,
        **result,
    }


def bootstrap_security(_data):
    """Fresh-VPS baseline using the exact same security implementations.

    Firewall protection of TCP/2222 is mandatory. BBR, Fail2Ban and logrotate
    remain supplemental so unsupported kernels/packages cannot destroy an
    otherwise valid node installation.
    """
    panel_path = Path("/opt/remnanode/panel-ip")
    if not panel_path.is_file() or panel_path.is_symlink():
        fail("managed panel IP missing")
    panel_ip = panel_path.read_text("utf-8").strip()
    try:
        panel = ipaddress.ip_address(panel_ip)
    except ValueError:
        fail("panel ipv4 required")
    if panel.version != 4 or not panel.is_global:
        fail("panel ipv4 invalid")

    peer = bootstrap_ssh_peer()
    trusted = [peer] if peer else []
    cfg = {
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
            "trusted_sources": trusted,
        },
        "firewall": {
            "enabled": True,
            "allowed_sources": [panel_ip + "/32"],
            "panel_ip": panel_ip,
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
    _validate(cfg)

    # Fresh installs are deliberately strict: Manager records this exact
    # profile as applied only after every managed group validates successfully.
    result = _apply(cfg)

    if peer:
        BOOTSTRAP_PEER.parent.mkdir(
            parents=True, exist_ok=True
        )
        replace_root_file(
            BOOTSTRAP_PEER, peer + "\n", 0o600
        )

    return {
        "bootstrap": True,
        "panel_api_protected": True,
        "bootstrap_ssh_peer": peer,
        **result,
    }
