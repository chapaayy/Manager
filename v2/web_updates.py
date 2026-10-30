"""Fixed-scope web update interface.

The web app cannot talk to Docker or run a shell. It can only create a
zero-content marker in the narrow host directory made available by installer.
A root-owned systemd.path service handles the actual update independently.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

SHARED = Path("/updater")
GITHUB_HEAD = (
    "https://api.github.com/repos/chapaayy/Manager/commits?"
    "sha=v2%2Frebuild-single-panel&per_page=1"
)
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def status() -> dict:
    path = SHARED / "status.json"
    if not path.is_file():
        return {
            "enabled": False, "state": "unavailable",
            "message": "Обновления из панели пока не активированы на сервере.",
            "installed_sha": "", "target_sha": "",
        }
    try:
        if path.stat().st_size > 8192:
            raise ValueError("Invalid status")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Invalid updater state")
    except (ValueError, OSError, UnicodeError):
        return {"enabled": False, "state": "unavailable",
                "message": "Не удалось прочитать состояние обновлений.",
                "installed_sha": "", "target_sha": ""}
    state = value.get("state", "unavailable")
    if state not in ("idle", "running", "succeeded", "failed"):
        state = "unavailable"
    return {
        "enabled": True, "state": state,
        "message": str(value.get("message") or "")[:350],
        "installed_sha": str(value.get("installed_sha") or "")[:40],
        "target_sha": str(value.get("target_sha") or "")[:40],
        "updated_at": value.get("updated_at", 0),
        "rolled_back": value.get("rolled_back", False) is True,
    }


def check_available() -> dict:
    previous = status()
    if not previous["enabled"]:
        return previous
    request = urllib.request.Request(
        GITHUB_HEAD, headers={"Accept": "application/vnd.github+json",
                              "User-Agent": "XPPN-Manager-Updater/2.2"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status != 200:
                raise ValueError("GitHub API unavailable")
            data = json.load(response)
        remote = data[0].get("sha", "") if isinstance(data, list) and data else ""
        if not SHA_RE.fullmatch(remote):
            raise ValueError("Invalid upstream commit")
    except (ValueError, OSError, urllib.error.URLError, json.JSONDecodeError):
        raise ValueError("Не удалось проверить GitHub. Попробуй ещё раз.") from None
    return {**previous, "latest_sha": remote,
            "update_available": previous["installed_sha"] != remote,
            "source": "chapaayy/Manager · v2/rebuild-single-panel"}


def request_update() -> dict:
    previous = status()
    if not previous["enabled"]:
        raise ValueError(previous["message"])
    if previous["state"] == "running":
        raise ValueError("Обновление уже выполняется.")
    # Never read, concatenate or pass a command, branch or path from the request.
    marker = SHARED / "request"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise ValueError("Запрос на обновление уже отправлен.") from None
    except OSError:
        raise ValueError("Серверный механизм обновления недоступен.") from None
    else:
        os.close(fd)
    return {"accepted": True, "message": "Запрос принят. Панель сама обновится и перезапустится."}
