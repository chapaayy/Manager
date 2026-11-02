"""Managed logrotate configuration and read-only log storage status."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

from .common import (
    fail,
    install_packages,
    replace_root_file,
    security_bool,
    security_int,
)


def logrotate_config(
    path: str, size_mb: int, archives: int, compress: bool
) -> str:
    directive = "compress" if compress else "nocompress"
    return (
        path
        + " {\n"
        "    daily\n"
        "    size "
        + str(size_mb)
        + "M\n"
        "    rotate "
        + str(archives)
        + "\n    "
        + directive
        + "\n"
        "    missingok\n"
        "    notifempty\n"
        "    copytruncate\n"
        "}\n"
    )


def apply_one_logrotate(
    cfg, file_path: str, log_path: str, name: str
):
    enabled = security_bool(cfg.get("enabled"), name + ".enabled")
    size_mb = security_int(
        cfg.get("size_mb"), name + ".size", 1, 2048
    )
    archives = security_int(
        cfg.get("archives"), name + ".archives", 1, 30
    )
    compress = security_bool(
        cfg.get("compress"), name + ".compress"
    )
    path = Path(file_path)

    if not enabled:
        if path.is_symlink():
            fail("managed logrotate linked")
        if path.is_file():
            path.unlink()
        return {"enabled": False}

    install_packages(["logrotate"])
    old = (
        path.read_bytes()
        if path.is_file() and not path.is_symlink()
        else None
    )
    replace_root_file(
        path,
        logrotate_config(log_path, size_mb, archives, compress),
        0o644,
    )
    proc = subprocess.run(
        ["logrotate", "-d", str(path)],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if proc.returncode:
        if old is None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        else:
            replace_root_file(path, old, 0o644)
        fail(name + " logrotate invalid")
    return {
        "enabled": True,
        "size_mb": size_mb,
        "archives": archives,
        "compress": compress,
    }


def apply_log_settings(cfg):
    if not isinstance(cfg, dict):
        fail("logs invalid")
    nginx = apply_one_logrotate(
        cfg.get("nginx", {}),
        "/etc/logrotate.d/xppn-nginx",
        "/opt/nginx/logs/*.log",
        "nginx",
    )
    node = apply_one_logrotate(
        cfg.get("remnanode", {}),
        "/etc/logrotate.d/xppn-remnanode",
        "/var/log/remnanode/*.log",
        "remnanode",
    )
    if shutil.which("systemctl"):
        subprocess.run(
            ["systemctl", "enable", "--now", "logrotate.timer"],
            capture_output=True,
            timeout=20,
        )
    return {"nginx": nginx, "remnanode": node}


def logrotate_ok(path: str) -> bool:
    target = Path(path)
    if (
        not target.is_file()
        or target.is_symlink()
        or not shutil.which("logrotate")
    ):
        return False
    try:
        return (
            subprocess.run(
                ["logrotate", "-d", str(target)],
                capture_output=True,
                timeout=10,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def directory_log_bytes(path: str) -> int:
    root = Path(path)
    total = 0
    if not root.is_dir() or root.is_symlink():
        return 0
    try:
        for item in root.iterdir():
            if (
                item.is_file()
                and not item.is_symlink()
                and item.name.endswith(".log")
            ):
                total += min(item.stat().st_size, 2**40)
    except OSError:
        return 0
    return total


def logrotate_state(path: str) -> dict:
    import re

    target = Path(path)
    state = {
        "enabled": False,
        "valid": False,
        "size_mb": None,
        "archives": None,
        "compress": None,
    }
    if not target.is_file() or target.is_symlink():
        return state
    state["enabled"] = True
    state["valid"] = logrotate_ok(path)
    try:
        for line in target.read_text("utf-8").splitlines():
            stripped = line.strip()
            match = re.fullmatch(r"size\s+([0-9]{1,4})M", stripped)
            if match:
                state["size_mb"] = int(match.group(1))
            match = re.fullmatch(r"rotate\s+([0-9]{1,2})", stripped)
            if match:
                state["archives"] = int(match.group(1))
            if stripped == "compress":
                state["compress"] = True
            if stripped == "nocompress":
                state["compress"] = False
    except (OSError, UnicodeError):
        pass
    return state
