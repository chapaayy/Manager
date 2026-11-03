#!/usr/bin/env bash
# Development-only loopback installer. Uses a separate checkout, project, port and volume.
set -Eeuo pipefail
umask 077

TARGET="/opt/xppn-manager-v2-dev"
BRANCH="v2/rebuild-single-panel"
REPO="https://github.com/chapaayy/Manager.git"
ENVFILE="$TARGET/v2/.env.dev"

[[ "$(id -u)" -eq 0 ]] || { echo "Запусти через sudo/root." >&2; exit 1; }
for bin in git docker python3; do
  command -v "$bin" >/dev/null || { echo "Для dev-режима нужен $bin" >&2; exit 1; }
done
docker compose version >/dev/null || { echo "Нужен Docker Compose v2" >&2; exit 1; }

if [[ ! -d "$TARGET/.git" ]]; then
  [[ ! -e "$TARGET" ]] || {
    echo "Папка $TARGET существует и не является git-репозиторием. Ничего не удаляем." >&2
    exit 1
  }
  git clone --branch "$BRANCH" --single-branch --depth 1 "$REPO" "$TARGET"
else
  [[ "$(git -C "$TARGET" branch --show-current)" == "$BRANCH" ]] ||
    { echo "В $TARGET другая ветка. Автоматический переход отменён." >&2; exit 1; }
  git -C "$TARGET" fetch --depth 1 origin "$BRANCH"
  git -C "$TARGET" merge --ff-only FETCH_HEAD
fi

if [[ ! -f "$ENVFILE" ]]; then
  python3 - "$ENVFILE" <<'PY'
import base64
import os
from pathlib import Path
import secrets
import sys

path=Path(sys.argv[1])
password=secrets.token_urlsafe(22)
session=secrets.token_urlsafe(48)
fernet=base64.urlsafe_b64encode(os.urandom(32)).decode()
path.write_text(
    "XPPN_V2_DB=/data/xppn-v2.db\n"
    "XPPN_V2_ADMIN_USER=admin\n"
    f"XPPN_V2_ADMIN_PASSWORD={password}\n"
    f"XPPN_V2_SESSION_SECRET={session}\n"
    f"XPPN_DATA_KEY={fernet}\n"
    "XPPN_V2_COOKIE_SECURE=0\n",
    encoding="utf-8",
)
path.chmod(0o600)
print("Созданы отдельные секреты для dev-копии.")
print("Логин: admin")
print("Пароль (сохрани):",password)
PY
else
  chmod 600 "$ENVFILE"
  echo "Существующие dev-секреты сохранены."
fi

cd "$TARGET"
docker compose   -p xppn-v2-dev   --project-directory "$TARGET/v2"   --env-file "$ENVFILE"   -f "$TARGET/v2/compose.dev.yml"   up -d --build

echo
echo "Dev-копия XPPN Manager запущена отдельно от production."
echo "Локальный адрес на VPS: http://127.0.0.1:8791"
echo "SSH-туннель: ssh -L 8791:127.0.0.1:8791 root@<IP_VPS>"
echo "После туннеля открой http://127.0.0.1:8791"
echo "Checkout: $TARGET"
echo "Docker project: xppn-v2-dev; production volume/контейнеры не используются."
