"""Read and atomically validate allowlisted managed configuration files."""
from __future__ import annotations

import hashlib
import os
import re

from .common import FILES, fail, run


def config_path(request):
    name = request.get("name")
    if not isinstance(name, str) or name not in FILES:
        fail("unsupported config")
    return FILES[name]


def inspect_config(request):
    path = config_path(request)
    raw = path.read_bytes()
    if len(raw) > 45000:
        fail("config too large")
    return {
        "name": request["name"],
        "content": raw.decode("utf-8"),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def update_nginx(request):
    if request.get("name") != "nginx":
        fail("only nginx configuration can currently be applied")
    content = request.get("content")
    expected = request.get("expected_sha256")
    if not isinstance(content, str) or not 0 < len(content.encode()) <= 35000:
        fail("invalid config size")
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        fail("missing revision")

    path = FILES["nginx"]
    old = path.read_bytes()
    if hashlib.sha256(old).hexdigest() != expected:
        fail("config was changed by another process")
    candidate = content.encode()
    if b"\x00" in candidate:
        fail("binary config not supported")

    backup = path.parent / (
        ".agent-nginx-backup-" + hashlib.sha256(old).hexdigest()[:16]
    )
    fd = os.open(
        backup,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(old)
        stream.flush()
        os.fsync(stream.fileno())

    def put(data: bytes):
        with open(path, "r+b") as stream:
            stream.seek(0)
            stream.write(data)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())

    put(candidate)
    try:
        run(["docker", "exec", "nginx", "nginx", "-t"], timeout=12)
        run(["docker", "exec", "nginx", "nginx", "-s", "reload"], timeout=12)
    except SystemExit:
        put(old)
        try:
            run(["docker", "exec", "nginx", "nginx", "-s", "reload"], timeout=12)
        except SystemExit:
            pass
        fail("nginx validation failed; original config restored")

    return {
        "name": "nginx",
        "applied": True,
        "sha256": hashlib.sha256(candidate).hexdigest(),
    }
