"""TCP congestion-control and qdisc management."""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

from .common import fail, inspect, replace_root_file, run, security_bool


def apply_tcp_settings(cfg):
    enabled = security_bool(cfg.get("enabled"), "tcp.enabled")
    cc = str(cfg.get("congestion_control", "")).strip().lower()
    qdisc = str(cfg.get("qdisc", "")).strip().lower()
    if cc not in {"bbr", "cubic", "reno"}:
        fail("unsupported congestion control")
    if qdisc not in {"fq", "fq_codel"}:
        fail("unsupported qdisc")

    managed = Path("/etc/sysctl.d/90-xppn-baseline.conf")
    previous = Path("/etc/xppn-baseline-previous")
    current_cc = inspect(["sysctl", "-n", "net.ipv4.tcp_congestion_control"]) or ""
    current_qdisc = inspect(["sysctl", "-n", "net.core.default_qdisc"]) or ""

    if enabled:
        if shutil.which("modprobe"):
            if cc == "bbr":
                subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, timeout=8)
            if qdisc == "fq":
                subprocess.run(["modprobe", "sch_fq"], capture_output=True, timeout=8)
            if qdisc == "fq_codel":
                subprocess.run(["modprobe", "sch_fq_codel"], capture_output=True, timeout=8)
        available = (
            inspect(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"])
            or ""
        ).split()
        if cc not in available:
            fail("requested congestion control unavailable")

        if (
            not managed.exists()
            and current_cc
            and current_qdisc
            and not previous.exists()
            and re.fullmatch(r"[a-z0-9_]+", current_cc)
            and re.fullmatch(r"[a-z0-9_]+", current_qdisc)
        ):
            replace_root_file(
                previous,
                "tcp_congestion_control="
                + current_cc
                + "\ndefault_qdisc="
                + current_qdisc
                + "\n",
                0o600,
            )

        old = (
            managed.read_bytes()
            if managed.is_file() and not managed.is_symlink()
            else None
        )
        content = (
            "# Managed by XPPN Manager. Only selected TCP congestion and default qdisc.\n"
            "net.core.default_qdisc = "
            + qdisc
            + "\nnet.ipv4.tcp_congestion_control = "
            + cc
            + "\n"
        )
        replace_root_file(managed, content, 0o644)
        try:
            run(["sysctl", "-p", str(managed)], timeout=12, limit=1500)
            if inspect(["sysctl", "-n", "net.ipv4.tcp_congestion_control"]) != cc:
                raise SystemExit(1)
            if inspect(["sysctl", "-n", "net.core.default_qdisc"]) != qdisc:
                raise SystemExit(1)
        except SystemExit:
            if old is None:
                try:
                    managed.unlink()
                except FileNotFoundError:
                    pass
            else:
                replace_root_file(managed, old, 0o644)
            if current_cc:
                subprocess.run(
                    [
                        "sysctl",
                        "-w",
                        "net.ipv4.tcp_congestion_control=" + current_cc,
                    ],
                    capture_output=True,
                    timeout=8,
                )
            if current_qdisc:
                subprocess.run(
                    ["sysctl", "-w", "net.core.default_qdisc=" + current_qdisc],
                    capture_output=True,
                    timeout=8,
                )
            fail("tcp settings failed validation")
        return {"enabled": True, "congestion_control": cc, "qdisc": qdisc}

    if managed.is_symlink():
        fail("managed sysctl unexpectedly linked")
    if managed.is_file():
        managed.unlink()

    restored = False
    if previous.is_file() and not previous.is_symlink():
        values = {}
        for line in previous.read_text("utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in ("tcp_congestion_control", "default_qdisc") and re.fullmatch(
                r"[a-z0-9_]+", value
            ):
                values[key] = value
        if values.get("tcp_congestion_control"):
            subprocess.run(
                [
                    "sysctl",
                    "-w",
                    "net.ipv4.tcp_congestion_control="
                    + values["tcp_congestion_control"],
                ],
                capture_output=True,
                timeout=8,
            )
            restored = True
        if values.get("default_qdisc"):
            subprocess.run(
                [
                    "sysctl",
                    "-w",
                    "net.core.default_qdisc=" + values["default_qdisc"],
                ],
                capture_output=True,
                timeout=8,
            )
            restored = True
    return {"enabled": False, "restored_previous": restored}


def active_qdisc():
    route = inspect(["ip", "-o", "route", "show", "default"], timeout=5) or ""
    match = re.search(r"(?:^|\s)dev\s+([A-Za-z0-9_.:-]+)", route)
    if not match:
        return {"interface": "", "qdisc": ""}
    iface = match.group(1)
    out = inspect(["tc", "qdisc", "show", "dev", iface], timeout=5) or ""
    qdisc = ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "qdisc":
            qdisc = parts[1]
            break
    return {"interface": iface, "qdisc": qdisc}
