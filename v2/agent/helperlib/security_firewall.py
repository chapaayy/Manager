"""Dedicated Remnawave Node API TCP/2222 firewall management."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shutil
import subprocess

from .common import (
    fail,
    inspect,
    replace_root_file,
    run,
    security_bool,
    security_networks,
)


def firewall_script(
    panel_ip: str,
    allowed: list[str],
    block_ipv6: bool,
    enabled: bool,
    legacy_ipv6: bool = False,
) -> str:
    old_panel = panel_ip
    lines = [
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "PORT=2222",
        "cleanup4(){",
        ' while iptables -C INPUT -p tcp --dport "$PORT" -j XPPN_NODE_API4 2>/dev/null; do iptables -D INPUT -p tcp --dport "$PORT" -j XPPN_NODE_API4; done',
        " iptables -F XPPN_NODE_API4 2>/dev/null || true",
        " iptables -X XPPN_NODE_API4 2>/dev/null || true",
        "}",
        "cleanup6(){",
        " if command -v ip6tables >/dev/null; then",
        '  while ip6tables -C INPUT -p tcp --dport "$PORT" -j XPPN_NODE_API6 2>/dev/null; do ip6tables -D INPUT -p tcp --dport "$PORT" -j XPPN_NODE_API6; done',
        "  ip6tables -F XPPN_NODE_API6 2>/dev/null || true",
        "  ip6tables -X XPPN_NODE_API6 2>/dev/null || true",
        " fi",
        "}",
        "cleanup4",
        "cleanup6",
    ]
    if old_panel:
        lines.append(
            'while iptables -C INPUT -p tcp --dport "$PORT" ! -s '
            + old_panel
            + ' -j DROP 2>/dev/null; do iptables -D INPUT -p tcp --dport "$PORT" ! -s '
            + old_panel
            + " -j DROP; done"
        )
    if legacy_ipv6:
        lines.append(
            'if command -v ip6tables >/dev/null && ip6tables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null; then ip6tables -D INPUT -p tcp --dport "$PORT" -j DROP; fi'
        )
    if not enabled:
        return "\n".join(lines) + "\n"

    ipv4 = []
    ipv6 = []
    for source in allowed:
        network = ipaddress.ip_network(source, strict=False)
        (ipv4 if network.version == 4 else ipv6).append(str(network))

    lines += ["iptables -N XPPN_NODE_API4"]
    for source in ipv4:
        lines.append(
            "iptables -A XPPN_NODE_API4 -s " + source + " -j ACCEPT"
        )
    lines += [
        "iptables -A XPPN_NODE_API4 -j DROP",
        'iptables -I INPUT 1 -p tcp --dport "$PORT" -j XPPN_NODE_API4',
    ]
    if block_ipv6 or ipv6:
        lines += [
            "if command -v ip6tables >/dev/null; then",
            " ip6tables -N XPPN_NODE_API6",
        ]
        for source in ipv6:
            lines.append(
                " ip6tables -A XPPN_NODE_API6 -s "
                + source
                + " -j ACCEPT"
            )
        lines += [
            " ip6tables -A XPPN_NODE_API6 -j DROP",
            ' ip6tables -I INPUT 1 -p tcp --dport "$PORT" -j XPPN_NODE_API6',
            "fi",
        ]
    return "\n".join(lines) + "\n"


def apply_firewall_settings(cfg):
    enabled = security_bool(cfg.get("enabled"), "firewall.enabled")
    block_ipv6 = security_bool(
        cfg.get("block_ipv6"), "firewall.block_ipv6"
    )
    allowed = security_networks(
        cfg.get("allowed_sources", []), "firewall.allowed"
    )
    panel_ip = str(cfg.get("panel_ip", "")).strip()
    old_panel = ""
    panel_path = Path("/opt/remnanode/panel-ip")
    if panel_path.is_file() and not panel_path.is_symlink():
        old_panel = panel_path.read_text("utf-8").strip()

    if enabled:
        try:
            panel = ipaddress.ip_address(panel_ip)
        except ValueError:
            fail("panel ipv4 required")
        if panel.version != 4 or not panel.is_global:
            fail("panel ipv4 invalid")
        if not any(
            panel in ipaddress.ip_network(item, strict=False)
            for item in allowed
        ):
            fail("firewall must allow panel ipv4")
    else:
        panel_ip = (
            old_panel
            if re.fullmatch(r"[0-9.]+", old_panel or "")
            else ""
        )

    script_path = Path("/usr/local/sbin/xppn-node-firewall")
    unit = Path("/etc/systemd/system/xppn-node-firewall.service")
    old_script = (
        script_path.read_bytes()
        if script_path.is_file() and not script_path.is_symlink()
        else None
    )
    legacy_ipv6 = bool(
        old_script
        and b"XPPN_NODE_API6" not in old_script
        and b"ip6tables -C INPUT -p tcp --dport 2222 -j DROP" in old_script
    )
    script = firewall_script(
        old_panel or panel_ip,
        allowed,
        block_ipv6,
        enabled,
        legacy_ipv6,
    )
    replace_root_file(script_path, script, 0o700)
    replace_root_file(
        unit,
        "[Unit]\n"
        "Description=Restrict Remnawave Node API to allowed sources\n"
        "Wants=docker.service\nAfter=docker.service\n"
        "[Service]\nType=oneshot\n"
        "ExecStart=/usr/local/sbin/xppn-node-firewall\n"
        "RemainAfterExit=yes\n"
        "[Install]\nWantedBy=multi-user.target\n",
        0o644,
    )
    run(["systemctl", "daemon-reload"], timeout=15, limit=1000)
    try:
        run([str(script_path)], timeout=20, limit=1800)
    except SystemExit:
        if old_script is not None:
            replace_root_file(script_path, old_script, 0o700)
            try:
                run([str(script_path)], timeout=20, limit=1800)
            except SystemExit:
                pass
        fail("firewall update failed")

    if enabled:
        replace_root_file(panel_path, panel_ip + "\n", 0o600)
        run(
            ["systemctl", "enable", "xppn-node-firewall.service"],
            timeout=15,
            limit=1000,
        )
        run(
            ["systemctl", "restart", "xppn-node-firewall.service"],
            timeout=20,
            limit=1000,
        )
    else:
        subprocess.run(
            [
                "systemctl",
                "disable",
                "--now",
                "xppn-node-firewall.service",
            ],
            capture_output=True,
            timeout=15,
        )
    return {
        "enabled": enabled,
        "allowed_sources": allowed,
        "block_ipv6": block_ipv6,
        "panel_ip": panel_ip if enabled else "",
    }


def iptables_has(args) -> bool:
    try:
        return (
            subprocess.run(
                args, capture_output=True, timeout=5, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def allowed_sources(program: str, chain: str) -> list[str]:
    raw = inspect([program, "-S", chain], timeout=6)
    if not raw:
        return []
    result = []
    for line in raw.splitlines():
        match = re.search(
            r"(?:^|\s)-s\s+([^\s]+).*\s-j\s+ACCEPT(?:\s|$)",
            line,
        )
        if not match:
            continue
        try:
            source = str(
                ipaddress.ip_network(match.group(1), strict=False)
            )
        except ValueError:
            continue
        if source not in result:
            result.append(source)
    return result[:40]
