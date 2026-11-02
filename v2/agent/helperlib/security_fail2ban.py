"""SSH-only Fail2Ban management and read-only ban history."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess

from .common import (
    admin_ipv4,
    fail,
    inspect,
    install_packages,
    replace_root_file,
    run,
    security_bool,
    security_int,
    security_networks,
)


def ssh_protection():
    raw = inspect(["fail2ban-client", "status", "sshd"], timeout=6)
    ips = []
    if raw:
        match = re.search(r"Banned IP list:\s*([^\r\n]*)", raw)
        if match:
            for item in match.group(1).split():
                try:
                    if isinstance(
                        ipaddress.ip_address(item), ipaddress.IPv4Address
                    ):
                        ips.append(item)
                except ValueError:
                    pass

    events = []
    out = inspect(
        [
            "journalctl",
            "-u",
            "fail2ban.service",
            "-n",
            "150",
            "--no-pager",
            "-o",
            "short-iso",
        ],
        timeout=8,
    )
    if out:
        for line in out.splitlines():
            match = re.search(r"\[sshd\]\s+(Ban|Unban)\s+([0-9.]+)", line)
            if not match:
                continue
            try:
                if not isinstance(
                    ipaddress.ip_address(match.group(2)), ipaddress.IPv4Address
                ):
                    continue
            except ValueError:
                continue
            events.append(
                {
                    "action": match.group(1).lower(),
                    "ip": match.group(2),
                    "when": line[:25],
                }
            )
    return {
        "banned_ips": ips[:50],
        "history": events[-30:],
        "banned_count": len(ips) if raw else None,
    }


def ssh_ports() -> str:
    raw = inspect(["/usr/sbin/sshd", "-T"], timeout=8) or ""
    ports = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "port" and parts[1].isdigit():
            number = int(parts[1])
            if 1 <= number <= 65535 and str(number) not in ports:
                ports.append(str(number))
    if not ports:
        fail("ssh port unavailable")
    return ",".join(ports)


def apply_fail2ban_settings(cfg, panel_ip: str):
    enabled = security_bool(cfg.get("enabled"), "fail2ban.enabled")
    maxretry = security_int(cfg.get("maxretry"), "fail2ban.maxretry", 1, 20)
    findtime = security_int(
        cfg.get("findtime_seconds"), "fail2ban.findtime", 60, 86400
    )
    bantime = security_int(
        cfg.get("bantime_seconds"),
        "fail2ban.bantime",
        60,
        604800,
        True,
    )
    trusted = security_networks(
        cfg.get("trusted_sources", []), "fail2ban.trusted"
    )
    conf = Path("/etc/fail2ban/jail.d/90-xppn-sshd.local")
    marker = Path("/var/lib/node-manager/fail2ban-managed")

    if not enabled:
        if conf.is_symlink():
            fail("managed fail2ban config linked")
        if conf.is_file():
            marker.parent.mkdir(parents=True, exist_ok=True)
            replace_root_file(marker, "managed\n", 0o600)
            conf.unlink()
            if shutil.which("fail2ban-client"):
                subprocess.run(
                    ["systemctl", "restart", "fail2ban.service"],
                    capture_output=True,
                    timeout=20,
                )
        return {"enabled": False}

    if shutil.which("fail2ban-client") and not conf.exists() and not marker.exists():
        fail("existing fail2ban needs review")
    if shutil.which("fail2ban-client") is None:
        install_packages(["fail2ban", "python3-systemd"])

    ports = ssh_ports()
    ignore = ["127.0.0.1/8", "::1"]
    for item in trusted:
        if item not in ignore:
            ignore.append(item)
    if panel_ip and panel_ip + "/32" not in ignore:
        ignore.append(panel_ip + "/32")

    content = (
        "# Managed by XPPN Manager. SSH jail only.\n"
        "[sshd]\n"
        "enabled = true\n"
        "backend = systemd\n"
        "mode = normal\n"
        "port = "
        + ports
        + "\nmaxretry = "
        + str(maxretry)
        + "\nfindtime = "
        + str(findtime)
        + "\nbantime = "
        + str(bantime)
        + "\nignoreip = "
        + " ".join(ignore)
        + "\n"
    )
    old = conf.read_bytes() if conf.is_file() and not conf.is_symlink() else None
    replace_root_file(conf, content, 0o644)
    marker.parent.mkdir(parents=True, exist_ok=True)
    replace_root_file(marker, "managed\n", 0o600)

    test = subprocess.run(
        ["fail2ban-client", "-t"],
        capture_output=True,
        timeout=20,
        check=False,
    )
    if test.returncode:
        if old is None:
            try:
                conf.unlink()
            except FileNotFoundError:
                pass
        else:
            replace_root_file(conf, old, 0o644)
        fail("fail2ban configuration invalid")

    proc = subprocess.run(
        ["systemctl", "enable", "--now", "fail2ban.service"],
        capture_output=True,
        timeout=25,
        check=False,
    )
    if proc.returncode:
        fail("fail2ban service unavailable")
    run(["fail2ban-client", "reload"], timeout=15, limit=2000)
    if inspect(["fail2ban-client", "status", "sshd"], timeout=8) is None:
        fail("fail2ban ssh jail unavailable")
    return {
        "enabled": True,
        "maxretry": maxretry,
        "findtime_seconds": findtime,
        "bantime_seconds": bantime,
        "trusted_sources": trusted,
    }


def install_ssh_protection(data):
    admin = admin_ipv4(data.get("admin_ip"))
    script = Path("/usr/local/libexec/node-manager-fail2ban")
    if not script.is_file() or script.is_symlink():
        fail("SSH protection installer not deployed")
    if data.get("confirmed") is not True:
        fail("explicit confirmation required")
    if (
        inspect(["systemctl", "is-active", "fail2ban.service"]) == "active"
        and inspect(["fail2ban-client", "status", "sshd"])
    ):
        return {"scheduled": False, "already_protected": True}
    run(
        [
            "systemd-run",
            "--collect",
            "--unit=xppn-ssh-protection-" + os.urandom(4).hex(),
            "--on-active=2s",
            str(script),
            admin,
        ],
        timeout=12,
        limit=1200,
    )
    return {
        "scheduled": True,
        "message": "SSH-only Fail2Ban installation scheduled",
    }


def bootstrap_fail2ban(data):
    admin = admin_ipv4(data.get("admin_ip"))
    panel_ip = ""
    panel = Path("/opt/remnanode/panel-ip")
    if panel.is_file() and not panel.is_symlink():
        candidate = panel.read_text("utf-8").strip()
        try:
            address = ipaddress.ip_address(candidate)
            if address.version == 4 and address.is_global:
                panel_ip = str(address)
        except ValueError:
            pass
    return apply_fail2ban_settings(
        {
            "enabled": True,
            "maxretry": 6,
            "findtime_seconds": 600,
            "bantime_seconds": 3600,
            "trusted_sources": [admin + "/32"],
        },
        panel_ip,
    )


def unban_ssh_ip(data):
    if data.get("confirmed") is not True:
        fail("explicit confirmation required")
    ip = admin_ipv4(data.get("ip"))
    if inspect(["systemctl", "is-active", "fail2ban.service"]) != "active":
        fail("fail2ban not active")
    status = ssh_protection()
    if ip not in status["banned_ips"]:
        fail("IP not in SSH ban list")
    run(
        ["fail2ban-client", "set", "sshd", "unbanip", ip],
        timeout=10,
        limit=240,
    )
    return {"unbanned": ip}


def managed_fail2ban_config():
    path = Path("/etc/fail2ban/jail.d/90-xppn-sshd.local")
    result = {
        "maxretry": None,
        "findtime": None,
        "bantime": None,
        "ignoreip": [],
    }
    if not path.is_file() or path.is_symlink():
        return result
    try:
        for line in path.read_text("utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = (
                part.strip() for part in stripped.split("=", 1)
            )
            if key in ("maxretry", "findtime", "bantime"):
                try:
                    result[key] = int(value)
                except ValueError:
                    pass
            elif key == "ignoreip":
                result["ignoreip"] = [
                    item for item in value.split() if len(item) <= 80
                ][:40]
    except (OSError, UnicodeError):
        pass
    return result
