#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="/opt/xppn-manager-v2"
BRANCH="v2/rebuild-single-panel"
REPO="https://github.com/chapaayy/Manager.git"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Запусти скрипт через sudo/root." >&2
  exit 1
fi
for bin in git docker python3; do
  command -v "$bin" >/dev/null || { echo "Для preview нужен $bin" >&2; exit 1; }
done
docker compose version >/dev/null || { echo "Для preview нужен Docker Compose v2" >&2; exit 1; }

if [[ ! -d "$TARGET/.git" ]]; then
  if [[ -e "$TARGET" ]]; then
    echo "Папка $TARGET уже существует и не является git-репозиторием. Ничего не удаляем." >&2
    exit 1
  fi
  git clone --branch "$BRANCH" --single-branch --depth 1 "$REPO" "$TARGET"
else
  current="$(git -C "$TARGET" branch --show-current)"
  if [[ "$current" != "$BRANCH" ]]; then
    echo "В $TARGET другая ветка ($current). Автоматический переход отменён." >&2
    exit 1
  fi
  git -C "$TARGET" fetch --depth 1 origin "$BRANCH"
  git -C "$TARGET" merge --ff-only FETCH_HEAD
fi

ENVFILE="$TARGET/v2/.env.preview"
if [[ ! -f "$ENVFILE" ]]; then
  umask 077
  python3 - "$ENVFILE" <<'PY'
import base64
import os
from pathlib import Path
import secrets
import sys

path = Path(sys.argv[1])
password = secrets.token_urlsafe(22)
session = secrets.token_urlsafe(48)
fernet = base64.urlsafe_b64encode(os.urandom(32)).decode()
content = (
    "XPPN_V2_DB=/data/xppn-v2.db\n"
    f"XPPN_V2_ADMIN_PASSWORD={password}\n"
    f"XPPN_V2_SESSION_SECRET={session}\n"
    f"XPPN_DATA_KEY={fernet}\n"
    "XPPN_V2_COOKIE_SECURE=0\n"
)
path.write_text(content, encoding="utf-8")
path.chmod(0o600)
print("Созданы ОТДЕЛЬНЫЕ секреты для XPPN v2 preview.")
print("Пароль администратора (сохрани, второй раз не показывается):", password)
PY
else
  chmod 600 "$ENVFILE"
  echo "Сохранены прежние секреты v2. Они не менялись."
fi

cd "$TARGET"
docker compose --project-directory "$TARGET/v2" -f "$TARGET/v2/compose.preview.yml" up -d --build
echo
echo "XPPN v2 запущен только на 127.0.0.1:8790. Основной XPPN v1 НЕ затронут."
echo "Для доступа с ПК создай SSH-туннель: ssh -L 8790:127.0.0.1:8790 root@<IP_ГЛАВНОГО_VPS>"
echo "Затем открой в браузере http://127.0.0.1:8790"
echo "Внимание: v2 пока не устанавливает ноды и не применяет Xray."
