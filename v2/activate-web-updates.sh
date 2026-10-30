#!/usr/bin/env bash
# ONE-TIME bootstrap for already installed XPPN Manager v2.
# No prompts, no DNS, no password reset and no changes to current Caddy.
set -Eeuo pipefail
umask 077
APP=/opt/xppn-manager-v2
ENVFILE="$APP/v2/.env.preview"
[[ $EUID -eq 0 ]] || { echo "Нужен sudo/root" >&2; exit 1; }
[[ -d "$APP/.git" && -f "$ENVFILE" ]] || {
  echo "На этом сервере не найдена установленная XPPN Manager v2" >&2; exit 1;
}
for c in git docker python3 curl systemctl flock; do
  command -v "$c" >/dev/null || { echo "Нужен $c" >&2; exit 1; }
done
docker compose version >/dev/null
mkdir -p /run/lock
exec 9>/run/lock/xppn-v2-install.lock
flock -n 9 || { echo "Сейчас выполняется другая операция установки" >&2; exit 1; }
[[ "$(git -C "$APP" branch --show-current)" == "v2/rebuild-single-panel" ]] ||
  { echo "Неправильная ветка в $APP" >&2; exit 1; }
[[ "$(git -C "$APP" remote get-url origin)" == "https://github.com/chapaayy/Manager.git" ]] ||
  { echo "GitHub origin отличается от ожидаемого, прекращаем" >&2; exit 1; }
if [[ -n "$(git -C "$APP" status --porcelain)" ]]; then
  echo "Обнаружены локальные изменения файлов. Не перезаписываем их." >&2
  exit 1
fi
echo "Загружаем кнопку обновления XPPN Manager..."
if [[ "$(git -C "$APP" rev-parse --is-shallow-repository)" == true ]]; then
  git -C "$APP" fetch -q --unshallow origin v2/rebuild-single-panel
else
  git -C "$APP" fetch -q origin v2/rebuild-single-panel
fi
git -C "$APP" merge --ff-only FETCH_HEAD

CADDY_V2="$(docker ps --filter label=com.docker.compose.project=xppn-v2-preview --filter label=com.docker.compose.service=caddy-v2 --format '{{.ID}}' | head -1)"
CADDY_V1="$(docker ps --filter label=com.docker.compose.project=xppn-manager --filter label=com.docker.compose.service=caddy --format '{{.ID}}' | head -1)"
MODE=public
NETWORK=""
set -- -p xppn-v2-preview --project-directory "$APP/v2" --env-file "$ENVFILE" -f "$APP/v2/compose.preview.yml"
if [[ -n "$CADDY_V2" ]]; then
  # v2 already owns HTTPS. Don't touch ports 80/443.
  set -- "$@" -f "$APP/v2/compose.public.yml"
elif [[ -n "$CADDY_V1" ]]; then
  MODE=shared
  NETWORK="$(docker inspect -f '{{range $name,$_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$CADDY_V1" | grep -m1 '^xppn-manager_' || true)"
  [[ -n "$NETWORK" ]] || { echo "Не найдена сеть Caddy v1" >&2; exit 1; }
  export XPPN_V2_EXISTING_NETWORK="$NETWORK"
  set -- "$@" -f "$APP/v2/compose.attach.yml"
else
  echo "Неизвестен текущий HTTPS-прокси. Не меняем домен и порты." >&2
  exit 1
fi
install -d -m 0700 -o 10001 -g 10001 /var/lib/xppn-v2-update
docker compose "$@" config --quiet
docker compose "$@" up -d --build --no-deps manager-v2
OK=0
for i in $(seq 1 35); do
  if curl -fsS --max-time 2 http://127.0.0.1:8790/api/health >/dev/null 2>&1; then
    OK=1; break
  fi
  sleep 2
done
[[ "$OK" == 1 ]] || {
  echo "Новая версия не прошла проверку, смотри docker compose logs. Caddy не изменялся." >&2
  exit 1;
}

install -d -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$APP/v2/host_updater.py" /usr/local/libexec/xppn-v2-updater.py
install -o root -g root -m 0644 "$APP/v2/systemd/xppn-v2-updater.path" /etc/systemd/system/xppn-v2-updater.path
install -o root -g root -m 0644 "$APP/v2/systemd/xppn-v2-updater.service" /etc/systemd/system/xppn-v2-updater.service
python3 - "$MODE" "$NETWORK" <<'PY'
import json
import os
import sys
from pathlib import Path
path=Path("/etc/xppn-v2-update.json")
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w",encoding="utf-8") as out:
    json.dump({"mode":sys.argv[1],"network":sys.argv[2]},out)
os.chmod(path,0o600)
PY
REVISION="$(git -C "$APP" rev-parse HEAD)"
python3 - "$REVISION" <<'PY'
import json
import os
from pathlib import Path
import sys
import time
path=Path("/var/lib/xppn-v2-update/status.json")
previous={}
if path.is_file():
    try: previous=json.loads(path.read_text())
    except (OSError,ValueError): pass
if previous.get("state")!="running":
    tmp=path.with_name(".status-activation-"+str(os.getpid()))
    tmp.write_text(json.dumps({"state":"idle","message":"Обновления с сайта активированы.",
        "installed_sha":sys.argv[1],"target_sha":"","rolled_back":False,
        "updated_at":int(time.time())},ensure_ascii=False))
    os.chmod(tmp,0o644)
    os.replace(tmp,path)
PY
systemctl daemon-reload
systemctl enable --now xppn-v2-updater.path
systemctl is-active --quiet xppn-v2-updater.path ||
  { echo "Служба обновлений не активна. systemctl status xppn-v2-updater.path" >&2; exit 1; }
echo
echo "ГОТОВО. Открой свой XPPN Manager и перейди в раздел «Обновления»."
echo "Дальше обновляй панель кнопкой. Логин, пароль, домен и прежние данные сохранены."
