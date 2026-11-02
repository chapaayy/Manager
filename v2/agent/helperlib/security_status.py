"""Read-only actual security state for Manager drift detection."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shutil

from .common import inspect
from .security_fail2ban import managed_fail2ban_config, ssh_protection
from .security_firewall import allowed_sources, iptables_has
from .security_logs import directory_log_bytes, logrotate_state
from .security_tcp import active_qdisc


def baseline_status():
    congestion = inspect(
        ["sysctl", "-n", "net.ipv4.tcp_congestion_control"]
    )
    available = inspect(
        ["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"]
    )
    qdisc = inspect(["sysctl", "-n", "net.core.default_qdisc"])
    active = active_qdisc()
    rule_file = Path("/etc/sysctl.d/90-xppn-baseline.conf")

    f2b_available = shutil.which("fail2ban-client") is not None
    f2b_active = (
        inspect(["systemctl", "is-active", "fail2ban.service"])
        == "active"
    )
    jail = (
        inspect(["fail2ban-client", "status", "sshd"])
        if f2b_active
        else None
    )
    banned = None
    if jail:
        hit = re.search(r"Currently banned:\s*(\d+)", jail)
        if hit:
            banned = int(hit.group(1))

    panel = Path("/opt/remnanode/panel-ip")
    panel_ip = (
        panel.read_text().strip()
        if panel.is_file() and not panel.is_symlink()
        else ""
    )
    panel_valid = False
    try:
        panel_valid = bool(ipaddress.IPv4Address(panel_ip))
    except ValueError:
        pass

    fwall = (
        inspect(
            ["systemctl", "is-active", "xppn-node-firewall.service"]
        )
        == "active"
    )
    fwall_enabled = (
        inspect(
            ["systemctl", "is-enabled", "xppn-node-firewall.service"]
        )
        == "enabled"
    )
    custom4 = iptables_has(
        [
            "iptables",
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            "2222",
            "-j",
            "XPPN_NODE_API4",
        ]
    )
    custom4_drop = (
        iptables_has(
            ["iptables", "-C", "XPPN_NODE_API4", "-j", "DROP"]
        )
        if custom4
        else False
    )
    custom4_panel = (
        iptables_has(
            [
                "iptables",
                "-C",
                "XPPN_NODE_API4",
                "-s",
                panel_ip + "/32",
                "-j",
                "ACCEPT",
            ]
        )
        if custom4 and panel_valid
        else False
    )

    legacy = False
    if panel_valid:
        legacy = iptables_has(
            [
                "iptables",
                "-C",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                "2222",
                "!",
                "-s",
                panel_ip,
                "-j",
                "DROP",
            ]
        )

    ipv6 = False
    if shutil.which("ip6tables"):
        custom6 = iptables_has(
            [
                "ip6tables",
                "-C",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                "2222",
                "-j",
                "XPPN_NODE_API6",
            ]
        )
        ipv6 = custom6 and iptables_has(
            ["ip6tables", "-C", "XPPN_NODE_API6", "-j", "DROP"]
        )
        if not ipv6:
            ipv6 = iptables_has(
                [
                    "ip6tables",
                    "-C",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    "2222",
                    "-j",
                    "DROP",
                ]
            )

    baseline_history = Path("/var/log/xppn-baseline-status.log")
    events = []
    if baseline_history.is_file() and not baseline_history.is_symlink():
        try:
            events = [
                value
                for value in baseline_history.read_text(
                    "utf-8"
                ).splitlines()[-30:]
                if re.fullmatch(r"[a-z0-9-]{3,65}", value)
            ]
        except (OSError, UnicodeError):
            pass

    install_state = Path("/var/lib/node-manager/ssh-protection.state")
    current_state = ""
    if install_state.is_file() and not install_state.is_symlink():
        try:
            raw = install_state.read_text("utf-8").strip()
            if re.fullmatch(r"[a-z0-9-]{3,60}", raw):
                current_state = raw
        except OSError:
            pass

    ssh_security = (
        ssh_protection()
        if jail is not None
        else {"banned_ips": [], "history": [], "banned_count": None}
    )
    nginx_rotate_state = logrotate_state(
        "/etc/logrotate.d/xppn-nginx"
    )
    node_rotate_state = logrotate_state(
        "/etc/logrotate.d/xppn-remnanode"
    )
    rotate_timer = (
        inspect(["systemctl", "is-active", "logrotate.timer"])
        == "active"
    )
    managed_f2b = managed_fail2ban_config()

    firewall_sources = (
        allowed_sources("iptables", "XPPN_NODE_API4")
        if custom4
        else []
    )
    if shutil.which("ip6tables"):
        firewall_sources += [
            item
            for item in allowed_sources(
                "ip6tables", "XPPN_NODE_API6"
            )
            if item not in firewall_sources
        ]

    peer_marker = Path("/var/lib/node-manager/bootstrap-ssh-peer")
    bootstrap_peer = ""
    if peer_marker.is_file() and not peer_marker.is_symlink():
        try:
            candidate = peer_marker.read_text("utf-8").strip()
            network = ipaddress.ip_network(candidate, strict=False)
            bootstrap_peer = str(network)
        except (OSError, ValueError):
            pass

    return {
        "security_settings_supported": True,
        "security_helper_ready": Path(
            "/usr/local/libexec/node-manager-helperlib.zip"
        ).is_file(),
        "security_helper_layout": "modular-v1",
        "bootstrap_ssh_peer": bootstrap_peer,
        "ssh_install_state": current_state,
        **ssh_security,
        "baseline_events": events,
        "tcp_congestion": congestion,
        "available_congestion": available,
        "default_qdisc": qdisc,
        "active_qdisc": active.get("qdisc", ""),
        "network_interface": active.get("interface", ""),
        "bbr_config_managed": (
            rule_file.is_file() and not rule_file.is_symlink()
        ),
        "fail2ban_installed": f2b_available,
        "fail2ban_active": f2b_active,
        "sshd_jail_active": jail is not None,
        "sshd_banned_count": banned,
        "fail2ban_maxretry": (
            managed_f2b["maxretry"] if jail else None
        ),
        "fail2ban_findtime": (
            managed_f2b["findtime"] if jail else None
        ),
        "fail2ban_bantime": (
            managed_f2b["bantime"] if jail else None
        ),
        "fail2ban_ignoreip": (
            managed_f2b["ignoreip"] if jail else []
        ),
        "panel_firewall_service_active": fwall,
        "panel_firewall_service_enabled": fwall_enabled,
        "panel_firewall_ipv4_rule": bool(
            (custom4 and custom4_drop and custom4_panel) or legacy
        ),
        "panel_firewall_ipv6_rule": ipv6,
        "panel_firewall_mode": (
            "managed-chain"
            if custom4
            else ("legacy" if legacy else "")
        ),
        "panel_firewall_panel_ip": (
            panel_ip if panel_valid else ""
        ),
        "panel_firewall_allowed_sources": firewall_sources,
        "nginx_logrotate": nginx_rotate_state["valid"],
        "remnanode_logrotate": node_rotate_state["valid"],
        "nginx_logrotate_state": nginx_rotate_state,
        "remnanode_logrotate_state": node_rotate_state,
        "logrotate_timer_active": rotate_timer,
        "nginx_log_bytes": directory_log_bytes(
            "/opt/nginx/logs"
        ),
        "remnanode_log_bytes": directory_log_bytes(
            "/var/log/remnanode"
        ),
        "read_only": True,
    }
