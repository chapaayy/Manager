#!/usr/bin/env python3
"""Tiny root-helper launcher.

Privileged implementations are packaged in node-manager-helperlib.zip. The
launcher owns only framing, action allowlisting and result size limits.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
# Source tree: helperlib/ sits next to this file.
# Installed VPS: the same package is a pinned zip next to the launcher.
for candidate in (
    HERE / "node-manager-helperlib.zip",
    HERE / "agent-helperlib.zip",
):
    if candidate.is_file() and not candidate.is_symlink():
        sys.path.insert(0, str(candidate))
sys.path.insert(0, str(HERE))

from helperlib.common import ACTIONS, fail
from helperlib.dispatcher import execute
from helperlib.security_firewall import firewall_script as _firewall_script
from helperlib.security_service import apply_security_settings
from helperlib.security_status import baseline_status
from helperlib.cleanup import (
    cleanup_managed as _cleanup_managed,
    finish_cleanup as _finish_cleanup,
)


def main():
    if len(sys.argv) != 2:
        fail("action not allowed")
    action = sys.argv[1]
    bootstrap = (
        action == "security.bootstrap"
        and Path(__file__).resolve()
        == Path("/root/.xppn-pending/agent-helper.py")
        and os.geteuid() == 0
        and not os.environ.get("SUDO_USER")
    )
    if action not in ACTIONS and not bootstrap:
        fail("action not allowed")

    raw = sys.stdin.buffer.read(51001)
    if len(raw) > 50000:
        fail("payload too large")
    try:
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            fail("payload must be an object")
        answer = execute(action, data)
        encoded = json.dumps(
            answer,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        if len(encoded) > 125000:
            fail("result too large")
        print(encoded)
    except (
        OSError,
        ValueError,
        KeyError,
        UnicodeError,
        subprocess.SubprocessError,
    ):
        fail("node helper action failed")


if __name__ == "__main__":
    main()
