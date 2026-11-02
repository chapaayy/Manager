"""Ordinary allowlisted Docker, service, logs and TLS helper operations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

from .common import (
    CONTAINERS,
    SYSTEMD,
    cert_paths,
    domain,
    fail,
    run,
)
from .config_ops import inspect_config, update_nginx


def execute_regular(action: str, data: dict):
    if action == "docker.status":
        result = []
        for name in sorted(CONTAINERS):
            proc = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .State}}",
                    name,
                ],
                capture_output=True,
                timeout=8,
                check=False,
            )
            if proc.returncode:
                result.append(
                    {
                        "name": name,
                        "running": False,
                        "installed": False,
                    }
                )
                continue
            state = json.loads(proc.stdout)
            result.append(
                {
                    "name": name,
                    "running": bool(state.get("Running")),
                    "installed": True,
                    "status": str(state.get("Status", ""))[:32],
                    "exit_code": state.get("ExitCode"),
                }
            )
        return {"containers": result}

    if action == "docker.restart":
        name = data.get("name")
        if name not in CONTAINERS:
            fail("container not allowed")
        run(
            ["docker", "restart", "--time", "8", name],
            timeout=30,
        )
        return {"restarted": name}

    if action == "logs.read":
        entries = {
            "xray-error": Path("/var/log/remnanode/error.log"),
            "xray-access": Path("/var/log/remnanode/access.log"),
            "nginx-access": Path("/opt/nginx/logs/access.log"),
            "nginx-error": Path("/opt/nginx/logs/error.log"),
            "certbot": Path(
                "/var/log/letsencrypt/letsencrypt.log"
            ),
        }
        source = data.get("source")
        if not isinstance(source, str) or source not in entries:
            fail("log source not allowed")
        path = entries[source]
        if path.is_symlink():
            fail("symlinked log source is not allowed")
        if not path.is_file():
            return {
                "source": source,
                "logs": "Лог пока не создан",
            }
        with open(path, "rb") as log:
            log.seek(0, 2)
            size = log.tell()
            log.seek(max(0, size - 65536))
            raw = log.read(65536)
        count = data.get("tail", 100)
        if (
            not isinstance(count, int)
            or not 1 <= count <= 200
        ):
            fail("invalid log tail")
        return {
            "source": source,
            "logs": b"\n"
            .join(raw.splitlines()[-count:])[-26000:]
            .decode("utf-8", "replace"),
        }

    if action == "docker.logs":
        name = data.get("name")
        if name not in CONTAINERS:
            fail("container not allowed")
        tail = data.get("tail", 80)
        if not isinstance(tail, int) or not 1 <= tail <= 200:
            fail("invalid tail")
        raw = subprocess.run(
            ["docker", "logs", "--tail", str(tail), name],
            capture_output=True,
            timeout=12,
            check=False,
        )
        if raw.returncode:
            fail("could not read container logs")
        logtext = (raw.stdout + raw.stderr)[-26000:].decode(
            "utf-8", "replace"
        )
        return {"name": name, "logs": logtext}

    if action == "service.status":
        result = []
        for name in sorted(SYSTEMD):
            check = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                timeout=7,
            )
            result.append(
                {
                    "name": name,
                    "active": check.returncode == 0,
                }
            )
        return {"services": result}

    if action == "service.restart":
        name = data.get("name")
        if name != "certbot.timer":
            fail("service restart not allowed")
        run(["systemctl", "restart", name], timeout=25)
        return {"restarted": name}

    if action == "cert.status":
        chain_path, key_path = cert_paths()
        chain = chain_path.read_bytes()
        key = key_path.read_bytes()
        if (
            not chain
            or not key
            or len(chain) + len(key) > 90000
        ):
            fail("invalid tls files")
        actual = domain()

        certificate_public = run(
            [
                "openssl",
                "x509",
                "-in",
                str(chain_path),
                "-pubkey",
                "-noout",
            ],
            timeout=8,
        )
        key_public = run(
            [
                "openssl",
                "pkey",
                "-in",
                str(key_path),
                "-pubout",
            ],
            timeout=8,
        )
        if certificate_public.strip() != key_public.strip():
            fail("certificate and private key do not match")
        hostcheck = run(
            [
                "openssl",
                "x509",
                "-in",
                str(chain_path),
                "-noout",
                "-checkhost",
                actual,
            ],
            timeout=8,
        )
        if "does match certificate" not in hostcheck:
            fail("certificate hostname mismatch")
        run(
            [
                "openssl",
                "x509",
                "-in",
                str(chain_path),
                "-noout",
                "-checkend",
                "3600",
            ],
            timeout=8,
        )

        mounts_raw = run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .Mounts}}",
                "remnanode",
            ],
            timeout=8,
            limit=15000,
        )
        mounts = json.loads(mounts_raw)
        if not any(
            mount.get("Source") == "/opt/nginx/certs"
            and mount.get("Destination") == "/opt/nginx/certs"
            and mount.get("RW") is False
            for mount in mounts
        ):
            fail(
                "Remnawave Node does not have the expected read-only TLS mount"
            )
        for check in (chain_path, key_path):
            run(
                [
                    "docker",
                    "exec",
                    "remnanode",
                    "test",
                    "-s",
                    str(check),
                ],
                timeout=8,
                limit=200,
            )
        details = run(
            [
                "openssl",
                "x509",
                "-in",
                str(chain_path),
                "-noout",
                "-enddate",
                "-fingerprint",
                "-sha256",
            ],
            timeout=10,
            limit=600,
        )
        return {
            "domain": actual,
            "details": details[:500],
            "certificate_sha256": hashlib.sha256(
                chain
            ).hexdigest(),
            "node_tls_mount_verified": True,
        }

    if action == "config.read":
        return inspect_config(data)
    if action == "config.apply":
        return update_nginx(data)
    fail("unsupported operation")
