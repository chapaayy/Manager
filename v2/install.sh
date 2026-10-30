#!/usr/bin/env bash
# XPPN Manager v2.1: domain, login, HTTPS, side by side with v1.
set -Eeuo pipefail
umask 077
APP=/opt/xppn-manager-v2
ENVFILE="$APP/v2/.env.preview"
V1_CADDY=/opt/xppn-manager/Caddyfile
BRANCH=v2/rebuild-single-panel
[[ $EUID -eq 0 ]] || { echo "Запусти через sudo/root" >&2; exit 1; }
[[ -r /dev/tty ]] || { echo "Запусти скачанный скрипт через sudo bash, не curl | bash" >&2; exit 1; }
for dep in git python3 docker curl flock; do
  if ! command -v "$dep" >/dev/null; then
    command -v apt-get >/dev/null || { echo "Не хватает $dep" >&2; exit 1; }
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    if [[ "$dep" == docker ]]; then
      apt-get install -y docker.io docker-compose-v2
      systemctl enable --now docker
    else
      apt-get install -y "$dep"
    fi
  fi
done
if ! docker compose version >/dev/null 2>&1; then apt-get install -y docker-compose-v2; fi
docker info >/dev/null || { echo "Docker недоступен" >&2; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/xppn-v2-install.lock
flock -n 9 || { echo "Установщик уже запущен" >&2; exit 1; }
echo "=== XPPN Manager v2.1: простой установщик ==="
if [[ ! -d "$APP/.git" ]]; then
  [[ ! -e "$APP" ]] || { echo "Папка $APP существует и не принадлежит этому проекту" >&2; exit 1; }
  git clone --branch "$BRANCH" --single-branch --depth 1 -q https://github.com/chapaayy/Manager.git "$APP"
else
  [[ "$(git -C "$APP" branch --show-current)" == "$BRANCH" ]] ||
    { echo "В $APP другая ветка" >&2; exit 1; }
  git -C "$APP" fetch -q --depth 1 origin "$BRANCH"
  git -C "$APP" merge --ff-only FETCH_HEAD
fi

PREV_DOMAIN=""
PREV_USER="admin"
if [[ -f "$ENVFILE" ]]; then
  PREV_DOMAIN="$(sed -n 's/^XPPN_V2_DOMAIN=//p' "$ENVFILE" | tail -1)"
  PREV_USER="$(sed -n 's/^XPPN_V2_ADMIN_USER=//p' "$ENVFILE" | tail -1)"
  [[ -n "$PREV_USER" ]] || PREV_USER=admin
fi
echo "Нужен домен с A-записью на этот VPS."
echo "Прежний домен: $PREV_DOMAIN"
read -r -p "Домен: " DOMAIN </dev/tty
[[ -n "$DOMAIN" ]] || DOMAIN="$PREV_DOMAIN"
read -r -p "Логин [$PREV_USER]: " USERNAME </dev/tty
[[ -n "$USERNAME" ]] || USERNAME="$PREV_USER"
if [[ -f "$ENVFILE" ]] && grep -Eq '^XPPN_V2_ADMIN_PASSWORD(_HASH)?=.' "$ENVFILE"; then
  echo "Пароль: Enter оставит прежний пароль"
else
  echo "Пароль: минимум 12 символов"
fi
read -r -s -p "Пароль: " PASS </dev/tty
echo
if [[ -n "$PASS" ]]; then
  read -r -s -p "Повтори пароль: " SECOND </dev/tty
  echo
  [[ "$PASS" == "$SECOND" ]] || { echo "Пароли не совпадают" >&2; exit 1; }
  unset SECOND
fi
if [[ -f /opt/xppn-manager/.env ]]; then
  LEGACY_DOMAIN="$(sed -n 's/^XPPN_DOMAIN=//p' /opt/xppn-manager/.env | tail -1)"
  [[ -z "$LEGACY_DOMAIN" || "$DOMAIN" != "$LEGACY_DOMAIN" ]] ||
    { echo "Этот домен занят v1. Выбери другой поддомен." >&2; exit 1; }
fi

mkdir -p /root/xppn-v2-backups
chmod 700 /root/xppn-v2-backups
STAMP="$(date -u +%Y%m%d-%H%M%S)-$$"
if [[ -f "$ENVFILE" ]]; then cp -p "$ENVFILE" "/root/xppn-v2-backups/env-$STAMP"; fi
printf '%s\0' "$PASS" | (cd "$APP" && python3 -m v2.setup_env --file "$ENVFILE" --domain "$DOMAIN" --username "$USERNAME")
unset PASS
DOMAIN="$(sed -n 's/^XPPN_V2_DOMAIN=//p' "$ENVFILE" | tail -1)"

echo "Собираем новую панель, не останавливая старую..."
CADDY="$(docker ps --filter label=com.docker.compose.project=xppn-manager --filter label=com.docker.compose.service=caddy --format '{{.ID}}' | head -1)"
set -- -p xppn-v2-preview --project-directory "$APP/v2" --env-file "$ENVFILE" -f "$APP/v2/compose.preview.yml"
MODE=standalone
if [[ -n "$CADDY" ]]; then
  MODE=shared
  [[ -f "$V1_CADDY" ]] && grep -q 'reverse_proxy manager:8000' "$V1_CADDY" ||
    { echo "Не распознан Caddyfile v1 — ничего не меняем" >&2; exit 1; }
  NETWORK="$(docker inspect -f '{{range $name,$_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$CADDY" | grep -m1 '^xppn-manager_' || true)"
  [[ -n "$NETWORK" ]] || { echo "Сеть Caddy v1 не найдена" >&2; exit 1; }
  export XPPN_V2_EXISTING_NETWORK="$NETWORK"
  set -- "$@" -f "$APP/v2/compose.attach.yml"
else
  if command -v ss >/dev/null && ss -ltnH | awk '{print $4}' | grep -Eq '(^|:)(80|443)$'; then
    echo "Порты 80/443 заняты другим сервисом. Не перезаписываем." >&2
    exit 1
  fi
  set -- "$@" -f "$APP/v2/compose.public.yml"
fi
docker compose "$@" config --quiet
docker compose "$@" up -d --build --no-deps manager-v2
READY=0
for _ in $(seq 1 35); do
  if curl -fsS --max-time 2 http://127.0.0.1:8790/api/health >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 2
done
if [[ "$READY" == 0 ]]; then
  echo "v2 не запустился, v1 не затронут." >&2
  docker compose "$@" logs --tail=75 manager-v2 >&2 || true
  exit 1
fi

if [[ "$MODE" == shared ]]; then
  BACKUP="/root/xppn-v2-backups/caddy-$STAMP"
  CANDIDATE="$(mktemp /tmp/xppn-caddy.XXXXXXXX)"
  cp -p "$V1_CADDY" "$BACKUP"
  (cd "$APP" && python3 -m v2.caddy_sites --original "$V1_CADDY" --candidate "$CANDIDATE" --domain "$DOMAIN")
  docker cp "$CANDIDATE" "$CADDY:/tmp/xppn-v2-test.Caddyfile"
  docker exec "$CADDY" caddy validate --config /tmp/xppn-v2-test.Caddyfile --adapter caddyfile
  # In-place write keeps the original bind-mounted inode in the Caddy container.
  cat "$CANDIDATE" > "$V1_CADDY"
  if ! docker exec "$CADDY" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile; then
    cat "$BACKUP" > "$V1_CADDY"
    docker exec "$CADDY" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile || true
    echo "Caddy восстановлен из резервной копии. HTTPS v2 не включён." >&2
    exit 1
  fi
  rm -f "$CANDIDATE"
else
  docker compose "$@" up -d caddy-v2
fi

TLS=0
for _ in $(seq 1 10); do
  if curl -fsS --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health" >/dev/null 2>&1; then
    TLS=1; break
  fi
  sleep 3
done
echo "══════════════════════════════════════════════"
echo "XPPN Manager v2.1"
echo "Ссылка: https://$DOMAIN"
echo "Логин: $USERNAME"
echo "Пароль: тот, что указал при установке"
echo "══════════════════════════════════════════════"
if [[ "$TLS" == 0 ]]; then
  echo "HTTPS ещё не готов: проверь DNS A-запись и доступность портов 80/443."
else
  echo "HTTPS и ответ менеджера проверены."
fi
echo "Старая версия v1 сохранена. Установка VPN-нод в v2 пока не подключена."
