"""Legacy managed-VPS cleanup, isolated from normal Agent operations."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shutil
import subprocess

from .common import domain, fail, run


def _check_cleanup_domain(request, prepared: bool = False) -> str:
    requested = request.get("domain")
    if not isinstance(requested, str) or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{1,249})\.[a-z]{2,63}",
        requested,
    ):
        fail("invalid cleanup target")
    actual = (
        Path("/var/lib/node-manager/cleanup-ready").read_text().strip()
        if prepared
        else domain()
    )
    if actual != requested:
        fail("cleanup target is different VPS")
    return requested


def _owned_path(path: Path) -> Path:
    if path.is_symlink():
        fail("managed path unexpectedly became a symlink")
    if path.exists() and not path.is_dir():
        fail("managed directory has unexpected type")
    return path


def _compose_down(file: Path, allowed: set[str]) -> None:
    if not file.is_file() or file.is_symlink():
        fail("managed compose file is missing or linked")
    services = run(
        ["docker", "compose", "-f", str(file), "config", "--services"],
        timeout=12,
        limit=2000,
    ).splitlines()
    if not services or set(services) != set(allowed):
        fail("managed compose was modified; refusing to remove other services")
    run(
        ["docker", "compose", "-f", str(file), "down", "--timeout", "5"],
        timeout=28,
        limit=2000,
    )


def _undo_managed_firewall() -> None:
    path = Path("/opt/remnanode/panel-ip")
    if not path.is_file() or path.is_symlink():
        fail("managed panel IP missing")
    address = path.read_text().strip()
    if ipaddress.ip_address(address).version != 4:
        fail("invalid managed firewall address")

    for program, chain in (
        ("iptables", "XPPN_NODE_API4"),
        ("ip6tables", "XPPN_NODE_API6"),
    ):
        if not shutil.which(program):
            continue
        rule = [
            program, "-C", "INPUT", "-p", "tcp", "--dport", "2222", "-j", chain
        ]
        while subprocess.run(
            rule, capture_output=True, timeout=7
        ).returncode == 0:
            run(
                [
                    program, "-D", "INPUT", "-p", "tcp", "--dport", "2222",
                    "-j", chain,
                ],
                timeout=10,
                limit=1000,
            )
        subprocess.run([program, "-F", chain], capture_output=True, timeout=7)
        subprocess.run([program, "-X", chain], capture_output=True, timeout=7)

    legacy = [
        "INPUT", "-p", "tcp", "--dport", "2222", "!", "-s", address,
        "-j", "DROP",
    ]
    if shutil.which("iptables"):
        while subprocess.run(
            ["iptables", "-C", *legacy],
            capture_output=True,
            timeout=7,
        ).returncode == 0:
            run(["iptables", "-D", *legacy], timeout=10, limit=1000)


def cleanup_managed(request):
    name = _check_cleanup_domain(request)
    node = _owned_path(Path("/opt/remnanode"))
    nginx = _owned_path(Path("/opt/nginx"))
    if not node.is_dir() or not nginx.is_dir():
        fail("managed directories absent; manual inspection required")
    if (node / "domain").is_symlink() or (node / "domain").read_text().strip() != name:
        fail("node identity does not match")

    _compose_down(node / "docker-compose.yml", {"remnanode"})
    _compose_down(nginx / "docker-compose.yml", {"nginx"})
    _undo_managed_firewall()

    renewal = Path("/etc/letsencrypt/renewal") / (name + ".conf")
    if renewal.is_symlink():
        fail("certbot renewal config is linked")
    certificate_deleted = renewal.is_file()
    if certificate_deleted:
        run(
            ["certbot", "delete", "--cert-name", name, "--non-interactive"],
            timeout=25,
            limit=2000,
        )

    subprocess.run(
        ["systemctl", "disable", "--now", "xppn-node-firewall.service"],
        capture_output=True,
        timeout=12,
    )
    managed_files = [
        Path("/etc/systemd/system/xppn-node-firewall.service"),
        Path("/etc/logrotate.d/xppn-remnanode"),
        Path("/etc/logrotate.d/xppn-nginx"),
        Path("/etc/fail2ban/jail.d/90-xppn-sshd.local"),
        Path("/etc/letsencrypt/renewal-hooks/deploy/xppn-node.sh"),
        Path("/usr/local/sbin/xppn-cert-refresh"),
        Path("/usr/local/sbin/xppn-node-firewall"),
        Path("/etc/sysctl.d/90-xppn-baseline.conf"),
    ]
    for path in managed_files:
        if path.is_symlink():
            fail("managed file unexpectedly linked")
        if path.is_file():
            path.unlink()

    run(["systemctl", "daemon-reload"], timeout=12, limit=1000)
    for path in (node, nginx, _owned_path(Path("/var/log/remnanode"))):
        if path.exists():
            shutil.rmtree(path)

    marker = Path("/var/lib/node-manager")
    marker.mkdir(mode=0o700, parents=True, exist_ok=True)
    file = marker / "cleanup-ready"
    if file.is_symlink():
        fail("cleanup marker unexpectedly linked")
    file.write_text(name + "\n")
    file.chmod(0o600)
    return {
        "cleaned": True,
        "node": name,
        "containers_removed": True,
        "certbot_certificate_deleted": certificate_deleted,
        "agent_remains": True,
    }


def finish_cleanup(request):
    name = _check_cleanup_domain(request, prepared=True)
    script = Path("/usr/local/libexec/node-manager-uninstall.sh")
    if not script.is_file() or script.is_symlink():
        fail("agent uninstall script missing")
    run(
        [
            "systemd-run", "--unit=node-manager-self-remove", "--on-active=20s",
            str(script),
        ],
        timeout=12,
        limit=3000,
    )
    return {"scheduled": True, "node": name, "verified_removed": False}
