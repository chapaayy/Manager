"""Root-side verification and scheduling for pinned Agent binary updates."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

from .common import fail, run


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req, fp, code, msg, headers, newurl
    ):
        return None


def trusted_agent_release():
    env = Path("/etc/node-manager/agent.env")
    if (
        env.is_symlink()
        or not env.is_file()
        or env.stat().st_size > 4096
    ):
        fail("trusted agent identity missing")

    values = {}
    for line in env.read_text("utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("MANAGER_URL", "NODE_ID", "AGENT_TOKEN"):
            values[key] = value

    manager = values.get("MANAGER_URL", "")
    node_id = values.get("NODE_ID", "")
    token = values.get("AGENT_TOKEN", "")
    parsed = urllib.parse.urlsplit(manager)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[0-9a-f-]{36}", node_id)
        or not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", token)
    ):
        fail("invalid trusted agent update source")

    req = urllib.request.Request(
        manager.rstrip("/")
        + "/api/agent/v1/update/manifest",
        headers={
            "Authorization": "Bearer " + token,
            "X-Node-Id": node_id,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(
            req, timeout=12
        ) as response:
            if response.status != 200:
                fail("trusted manifest unavailable")
            raw = response.read(4097)
            if len(raw) > 4096:
                fail("trusted manifest too large")
        manifest = json.loads(raw)
    except (
        OSError,
        ValueError,
        UnicodeError,
        urllib.error.URLError,
    ):
        fail("cannot verify trusted Manager release")

    arch = {
        "x86_64": "amd64",
        "aarch64": "arm64",
    }.get(os.uname().machine)
    if not arch or not isinstance(manifest, dict):
        fail("unsupported verified agent release")
    item = manifest.get("binaries", {}).get(arch)
    if not isinstance(item, dict):
        fail("trusted agent release missing architecture")
    return item


def schedule_agent_update(data):
    version = data.get("version")
    expected = data.get("sha256")
    if not isinstance(version, str) or not re.fullmatch(
        r"1\.[0-9]{1,3}\.[0-9]{1,3}", version
    ):
        fail("invalid agent update version")
    if not isinstance(expected, str) or not re.fullmatch(
        r"[a-f0-9]{64}", expected
    ):
        fail("invalid agent checksum")

    path = Path("/var/lib/node-manager/update.bin")
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 14000000
    ):
        fail("staged agent update missing or invalid")

    release = trusted_agent_release()
    if (
        release.get("version") != version
        or release.get("sha256") != expected
        or release.get("size") != path.stat().st_size
    ):
        fail("agent update is not in trusted Manager release")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        fail("staged agent update checksum mismatch")

    updater = Path("/usr/local/libexec/node-manager-updater")
    if not updater.is_file() or updater.is_symlink():
        fail("agent updater missing")
    run(
        [
            "systemd-run",
            "--collect",
            "--unit=xppn-agent-upgrade-" + expected[:12],
            "--on-active=4s",
            str(updater),
            version,
            expected,
        ],
        timeout=10,
        limit=1200,
    )
    return {
        "scheduled": True,
        "version": version,
        "sha256": expected,
    }
