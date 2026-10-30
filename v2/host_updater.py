"""Root-owned XPPN Manager v2 host updater.

Triggered by a fixed-name marker file via systemd.path; never reads user
parameters, invokes arbitrary commands or exposes the Docker socket to the
internet-facing app. This file is copied to /usr/local/libexec (root-only)
by the installer, not executed from a writable web-app volume.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

APP = Path("/opt/xppn-manager-v2")
STATE = Path("/var/lib/xppn-v2-update")
BACKUP = Path("/root/xppn-v2-backups")
CONFIG = Path("/etc/xppn-v2-update.json")
LOCK = Path("/run/lock/xppn-v2-host-update.lock")
REPO = "https://github.com/chapaayy/Manager.git"
BRANCH = "v2/rebuild-single-panel"
CONTAINER = "xppn-v2-preview-manager-v2-1"


def call(*args: str, timeout: int = 150) -> str:
    result = subprocess.run(args, cwd=APP, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        # Logs from docker/git may include secrets and should never be sent to the UI.
        raise RuntimeError(f"Команда {args[0]} завершилась ошибкой ({result.returncode})")
    return result.stdout.strip()


def write_state(stage: str, message: str, *, installed_sha: str = "",
                target_sha: str = "", rollback: bool = False) -> None:
    record = {
        "state": stage, "message": message[:350],
        "installed_sha": installed_sha[:40], "target_sha": target_sha[:40],
        "rolled_back": rollback, "updated_at": int(time.time()),
    }
    fd, path = tempfile.mkstemp(prefix=".status-", dir=STATE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(path, 0o644)
        os.replace(path, STATE / "status.json")
    finally:
        if os.path.lexists(path):
            os.unlink(path)


def get_revision() -> str:
    return call("git", "rev-parse", "HEAD")


def compose() -> list[str]:
    settings = json.loads(CONFIG.read_text(encoding="utf-8"))
    mode = settings.get("mode")
    args = [
        "docker", "compose", "-p", "xppn-v2-preview",
        "--project-directory", str(APP / "v2"),
        "--env-file", str(APP / "v2" / ".env.preview"),
        "-f", str(APP / "v2" / "compose.preview.yml"),
    ]
    if mode == "public":
        args += ["-f", str(APP / "v2" / "compose.public.yml")]
    elif mode == "shared":
        network = settings.get("network", "")
        if not network or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in network):
            raise RuntimeError("Некорректная сохранённая сеть Caddy")
        os.environ["XPPN_V2_EXISTING_NETWORK"] = network
        args += ["-f", str(APP / "v2" / "compose.attach.yml")]
    else:
        raise RuntimeError("Режим подключения к Caddy не определён")
    return args


def healthy(timeout: int = 95) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8790/api/health", timeout=3) as response:
                payload = json.load(response)
                if response.status == 200 and payload.get("ok") is True:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(2)
    return False


def snapshot(timestamp: str) -> None:
    BACKUP.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP, 0o700)
    env = APP / "v2" / ".env.preview"
    shutil.copy2(env, BACKUP / ("v2-env-before-update-" + timestamp))
    os.chmod(BACKUP / ("v2-env-before-update-" + timestamp), 0o600)
    # SQLite online backup through the running application container, not a live copy
    # of db + WAL files. This stays entirely off the web-update shared directory.
    image_backup = "/data/.xppn-update-backup.sqlite"
    code = (
        "import sqlite3;"
        "source=sqlite3.connect('/data/xppn-v2.db');"
        "dest=sqlite3.connect('/data/.xppn-update-backup.sqlite');"
        "source.backup(dest);dest.close();source.close()"
    )
    call("docker", "exec", CONTAINER, "python", "-c", code, timeout=40)
    target = BACKUP / ("v2-database-before-update-" + timestamp + ".sqlite")
    try:
        call("docker", "cp", CONTAINER + ":" + image_backup, str(target))
        os.chmod(target, 0o600)
    finally:
        try:
            call("docker", "exec", CONTAINER, "rm", "-f", image_backup)
        except Exception:
            pass


def restart() -> None:
    command = compose()
    call(*(command + ["config", "--quiet"]), timeout=40)
    call(*(command + ["up", "-d", "--build", "--no-deps", "manager-v2"]), timeout=300)
    if not healthy():
        raise RuntimeError("Новая панель не прошла HTTP-проверку после перезапуска")


def perform_update() -> None:
    if not (APP / ".git").is_dir() or not CONFIG.is_file():
        write_state("failed", "Не найдено установленное приложение или настройки обновления")
        return
    previous = get_revision()
    write_state("running", "Проверяем GitHub и сохраняем резервную копию…", installed_sha=previous)
    if call("git", "remote", "get-url", "origin") != REPO:
        raise RuntimeError("Git remote отличается от разрешённого репозитория")
    if call("git", "branch", "--show-current") != BRANCH:
        raise RuntimeError("Установлена другая ветка Git. Автообновление запрещено")
    if call("git", "status", "--porcelain"):
        raise RuntimeError("В файлах приложения есть локальные изменения; требуется проверка")
    call("git", "fetch", "--quiet", "origin", BRANCH, timeout=120)
    next_sha = call("git", "rev-parse", "FETCH_HEAD")
    if next_sha == previous:
        write_state("succeeded", "У тебя уже установлена последняя версия.", installed_sha=previous, target_sha=next_sha)
        return
    subprocess.run(["git", "merge-base", "--is-ancestor", previous, next_sha],
                   cwd=APP, check=True, capture_output=True, timeout=20)
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    snapshot(timestamp)
    write_state("running", "Обновление загружено. Собираем новую версию…",
                installed_sha=previous, target_sha=next_sha)
    applied = False
    try:
        call("git", "merge", "--ff-only", next_sha, timeout=45)
        applied = True
        restart()
    except Exception as exc:
        if not applied:
            raise
        write_state("running", "Проверка не прошла. Возвращаем предыдущую версию…",
                    installed_sha=previous, target_sha=next_sha)
        try:
            call("git", "reset", "--hard", previous, timeout=30)
            restart()
            write_state("failed", "Новая версия не прошла проверку, предыдущая восстановлена. "
                        "Резервная копия базы сохранена.",
                        installed_sha=previous, target_sha=next_sha, rollback=True)
        except Exception:
            write_state("failed", "Не удалось восстановить предыдущую версию. "
                        "Не меняй данные; проверь системный журнал обновления.",
                        installed_sha=previous, target_sha=next_sha, rollback=False)
        return
    write_state("succeeded", "Панель успешно обновлена и проверена.", installed_sha=next_sha, target_sha=next_sha)


def main() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        marker = STATE / "request"
        if not marker.is_file() or marker.is_symlink():
            return
        # The only input from the web app is this fixed-name empty marker.
        marker.unlink()
        old = ""
        try:
            old = get_revision()
            perform_update()
        except Exception as exc:
            print("XPPN updater:", repr(exc), file=sys.stderr)
            write_state("failed", "Ошибка обновления. Действующая версия сохранена; "
                        "подробности в journalctl -u xppn-v2-updater.",
                        installed_sha=old)


if __name__ == "__main__":
    main()
