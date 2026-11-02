"""Shared allowlists, validation and bounded process/file primitives."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

FILES = {
    "nginx": Path("/opt/nginx/nginx.conf"),
    "nginx-compose": Path("/opt/nginx/docker-compose.yml"),
    "node-compose": Path("/opt/remnanode/docker-compose.yml"),
}
CONTAINERS = {"nginx", "remnanode"}
SYSTEMD = {"docker.service", "certbot.timer", "xppn-node-firewall.service"}

PUBLIC_ACTIONS = {
    "docker.status",
    "docker.logs",
    "docker.restart",
    "service.status",
    "service.restart",
    "logs.read",
    "cert.status",
    "config.read",
    "config.apply",
    "baseline.status",
    "agent.update",
    "node.cleanup",
    "node.cleanup.finish",
    "security.fail2ban.install",
    "security.fail2ban.unban",
    "security.settings.apply",
}
ACTIONS = PUBLIC_ACTIONS


def fail(message: str):
    print(str(message)[:120], file=sys.stderr)
    raise SystemExit(1)


def run(args, timeout: int = 15, limit: int = 34000) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("action execution failed")
    if result.returncode or len(result.stdout) > limit:
        fail("action failed validation")
    return result.stdout.decode("utf-8", "replace")


def inspect(args, timeout: int = 5):
    """Bounded, non-mutating observation; never executes a shell string."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if completed.returncode:
            return None
        return completed.stdout.decode("utf-8", "replace").strip()[:12000]
    except (OSError, subprocess.TimeoutExpired):
        return None


def domain() -> str:
    value = Path("/opt/remnanode/domain").read_text().strip().lower()
    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{1,249})\.[a-z]{2,63}",
        value,
    ):
        fail("invalid node domain")
    return value


def cert_paths():
    name = domain()
    root = Path("/opt/nginx/certs")
    return (
        root / (name + "_fullchain.pem"),
        root / (name + "_privkey.key"),
    )


def security_bool(value, name: str) -> bool:
    if not isinstance(value, bool):
        fail(name + " must be boolean")
    return value


def security_int(
    value,
    name: str,
    minimum: int,
    maximum: int,
    allow_minus_one: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(name + " must be integer")
    if allow_minus_one and value == -1:
        return value
    if not minimum <= value <= maximum:
        fail(name + " out of range")
    return value


def security_networks(value, name: str, limit: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        fail(name + " invalid")
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 80:
            fail(name + " invalid")
        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            fail(name + " invalid")
        canonical = str(network)
        if canonical not in result:
            result.append(canonical)
    return result


def admin_ipv4(raw) -> str:
    if not isinstance(raw, str) or len(raw) > 45:
        fail("administrator IP required")
    try:
        address = ipaddress.ip_address(raw)
        if address.version != 4 or not address.is_global:
            fail("administrator IP must be public IPv4")
    except ValueError:
        fail("administrator IP invalid")
    return str(address)


def replace_root_file(path: Path, content, mode: int = 0o644) -> None:
    if path.is_symlink():
        fail("managed file unexpectedly linked")
    data = content.encode("utf-8") if isinstance(content, str) else content
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".xppn-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def install_packages(packages: list[str]) -> None:
    missing = [name for name in packages if shutil.which(name) is None]
    if not missing:
        return
    proc = subprocess.run(
        [
            "apt-get",
            "-o",
            "DPkg::Lock::Timeout=60",
            "install",
            "-y",
            "-qq",
            *packages,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=150,
        check=False,
        env={
            **os.environ,
            "DEBIAN_FRONTEND": "noninteractive",
            "NEEDRESTART_MODE": "l",
        },
    )
    if proc.returncode:
        fail("package installation failed")


def bootstrap_ssh_peer() -> str:
    """Return the current bootstrap SSH peer as a canonical host CIDR."""
    raw = os.environ.get("SSH_CONNECTION", "") or os.environ.get("SSH_CLIENT", "")
    first = raw.split()[0] if raw.split() else ""
    try:
        address = ipaddress.ip_address(first)
    except ValueError:
        return ""
    suffix = 32 if address.version == 4 else 128
    return f"{address}/{suffix}"
