#!/usr/bin/env bash
# XPPN Manager: single entry point for installation, migration and repair.
# Public code source: https://github.com/chapaayy/Manager
set -Eeuo pipefail
umask 077
APP=/opt/xppn-manager
BACKUP_ROOT=/root/xppn-manager-backups
[[ $EUID -eq 0 ]] || { echo 'Run as root: sudo bash install.sh' >&2; exit 1; }
for c in python3 tar curl flock; do command -v "$c" >/dev/null || { echo "Missing $c" >&2; exit 1; }; done
mkdir -p /run/lock
exec 9>/run/lock/xppn-manager-install.lock
flock -n 9 || { echo 'Another XPPN installation is running' >&2; exit 1; }
STAGE=$(mktemp -d /tmp/xppn-install.XXXXXXXX)
trap 'rm -rf "$STAGE"' EXIT
SOURCE="$STAGE/source"
mkdir -p "$SOURCE"
if [[ $# -gt 0 ]] && [[ "$1" == '--local' ]]; then
  HERE=$(cd "$(dirname "$BASH_SOURCE")" && pwd)
  [[ -f "$HERE/manager/app.py" ]] || { echo 'Local release sources missing' >&2; exit 1; }
  tar -C "$HERE" -cf - --exclude='.git' --exclude='.env' --exclude='__pycache__' . | tar -xf - -C "$SOURCE"
else
  echo '[1/6] Downloading XPPN Manager sources...'
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 \
    https://codeload.github.com/chapaayy/Manager/tar.gz/refs/heads/main \
    -o "$STAGE/source.tar.gz"
  tar -xzf "$STAGE/source.tar.gz" --strip-components=1 -C "$SOURCE"
fi
for f in docker-compose.yml manager/Dockerfile manager/app.py manager/cli.py deploy/update-worker.sh deploy/install-updater.sh; do
  [[ -s "$SOURCE/$f" ]] || { echo "Missing release file: $f" >&2; exit 1; }
done
python3 -m compileall -q "$SOURCE/manager" "$SOURCE/agent"
bash -n "$SOURCE/deploy/update-worker.sh" "$SOURCE/deploy/install-updater.sh" "$SOURCE/install.sh"
mkdir -p "$APP" "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
if [[ ! -e "$APP/.env" ]]; then
  cp "$SOURCE/.env.example" "$APP/.env"
  chmod 600 "$APP/.env"
  echo 'Edit XPPN_DOMAIN, XPPN_ADMIN_USER, XPPN_ADMIN_PASSWORD and save the .env file.'
  if [[ -t 0 && -t 1 ]]; then
    if command -v nano >/dev/null; then
      nano "$APP/.env" </dev/tty >/dev/tty
    elif command -v vi >/dev/null; then
      vi "$APP/.env" </dev/tty >/dev/tty
    else
      echo "Edit $APP/.env with a text editor and rerun this installer"
      exit 2
    fi
  else
    echo "Edit $APP/.env and rerun this installer"
    exit 2
  fi
fi
chmod 600 "$APP/.env"
EXISTING_DB_BEFORE=0
if command -v docker >/dev/null && docker volume inspect xppn-manager_manager-data >/dev/null 2>&1; then
  EXISTING_DB_BEFORE=1
fi
ENV_PATH="$APP/.env" XPPN_EXISTING_DB="$EXISTING_DB_BEFORE" python3 - <<'PY'
import base64,os,re,secrets,sys
from pathlib import Path
p=Path(os.environ['ENV_PATH'])
txt=p.read_text()
vals={}
for line in txt.splitlines():
    m=re.match(r'^([A-Z][A-Z0-9_]*)=(.*)$',line.strip())
    if m:vals[m.group(1)]=m.group(2).strip().strip('"\'')
domain=vals.get('XPPN_DOMAIN','').lower()
if (not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain)
        or domain in {'manager.example.com','example.com'}):
    sys.exit('Set your real XPPN_DOMAIN in /opt/xppn-manager/.env')
user=vals.get('XPPN_ADMIN_USER','admin') or 'admin'
if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}',user):
    sys.exit('Invalid XPPN_ADMIN_USER')
password=vals.get('XPPN_ADMIN_PASSWORD','')
if password and len(password)<8:
    print('WARNING: Short administrator password. Restrict public access to this panel.', file=sys.stderr)
if os.getenv('XPPN_EXISTING_DB')=='1' and not vals.get('XPPN_DATA_KEY'):
    sys.exit('Existing database detected: restore original XPPN_DATA_KEY before installation')
updates={
 'XPPN_DOMAIN':domain,
 'XPPN_PUBLIC_URL':'https://'+domain,
 'XPPN_ALLOWED_HOSTS':domain+',localhost,127.0.0.1',
 'XPPN_SECURE_COOKIES':'true',
 'XPPN_ADMIN_USER':user,
 'XPPN_SESSION_SECRET':vals.get('XPPN_SESSION_SECRET') or secrets.token_urlsafe(48),
 'XPPN_DATA_KEY':vals.get('XPPN_DATA_KEY') or base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
 'XPPN_ALLOW_PRIVATE_SSH':vals.get('XPPN_ALLOW_PRIVATE_SSH','false'),
 'XPPN_UPDATE_ENABLED':'true'}
if len(updates['XPPN_SESSION_SECRET'])<32:
    sys.exit('XPPN_SESSION_SECRET is too short')
try:
    assert len(base64.urlsafe_b64decode(updates['XPPN_DATA_KEY']))==32
except Exception:
    sys.exit('Invalid XPPN_DATA_KEY; do not regenerate secrets for an existing server')
lines=txt.splitlines()
for key,value in updates.items():
    found=False
    for i,line in enumerate(lines):
        if re.match(r'^'+re.escape(key)+r'=',line):
            lines[i]=key+'='+value;found=True;break
    if not found:lines.append(key+'='+value)
p.write_text('\n'.join(lines).rstrip()+'\n')
p.chmod(0o600)
print('[2/6] .env validated; secrets preserved or generated')
PY
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  command -v apt-get >/dev/null || { echo 'Docker Compose v2 required; install Docker first' >&2; exit 1; }
  echo '[3/6] Installing Docker + Compose...'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io docker-compose-v2
  systemctl enable --now docker
fi
docker info >/dev/null || { echo 'Docker daemon is unavailable' >&2; exit 1; }
VOLUME=xppn-manager_manager-data
EXISTING_DB=0
docker volume inspect "$VOLUME" >/dev/null 2>&1 && EXISTING_DB=1
systemctl stop xppn-manager-updater.timer 2>/dev/null || true
BACKUP="$BACKUP_ROOT/$(date -u +%Y%m%d-%H%M%S)-$$"
mkdir -p "$BACKUP";chmod 700 "$BACKUP"
cp -p "$APP/.env" "$BACKUP/.env"
HAD_APP=0
if [[ -f "$APP/docker-compose.yml" ]]; then
  HAD_APP=1
  tar -C "$APP" -czf "$BACKUP/source.tar.gz" --exclude='./.env' --exclude='./.git' .
fi
OLD_IMAGE=''
if docker image inspect xppn-manager-manager >/dev/null 2>&1; then
  OLD_IMAGE="xppn-manager:before-install-$(date +%s)-$$"
  docker image tag xppn-manager-manager "$OLD_IMAGE"
fi
cp -p "$APP/.env" "$SOURCE/.env"
chmod 600 "$SOURCE/.env"
echo '[4/6] Building candidate image before touching running Manager...'
docker compose -p xppn-manager -f "$SOURCE/docker-compose.yml" --env-file "$SOURCE/.env" build manager
APPLIED=0
STOPPED=0
rollback(){
  local rc=$?
  trap - ERR
  echo "Install failed; attempting recovery from $BACKUP" >&2
  if [[ "$STOPPED" == 1 ]]; then
    if [[ "$APPLIED" == 1 && "$HAD_APP" == 1 && -f "$BACKUP/source.tar.gz" ]]; then
      tar -xzf "$BACKUP/source.tar.gz" -C "$APP" || true
      cp -p "$BACKUP/.env" "$APP/.env" || true
    fi
    if [[ "$APPLIED" == 1 && "$EXISTING_DB" == 1 && -s "$BACKUP/data.tar.gz" ]]; then
      docker run --rm --network none -v "$VOLUME:/data" -v "$BACKUP:/backup:ro" alpine:3.20 \
        sh -eu -c 'cd /data && find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + && tar -xzf /backup/data.tar.gz' || true
    fi
    if [[ -n "$OLD_IMAGE" ]]; then docker image tag "$OLD_IMAGE" xppn-manager-manager || true; fi
    if [[ "$HAD_APP" == 1 ]]; then
      (cd "$APP" && docker compose --profile public up -d --no-build --no-deps manager) || true
    fi
  fi
  echo 'Updater remains stopped until an installation succeeds' >&2
  exit "$rc"
}
trap rollback ERR
if [[ "$HAD_APP" == 1 ]]; then
  (cd "$APP" && docker compose --profile public stop manager)
  STOPPED=1
fi
if [[ "$EXISTING_DB" == 1 ]]; then
  docker run --rm --network none -v "$VOLUME:/source:ro" -v "$BACKUP:/backup" alpine:3.20 \
    sh -eu -c 'cd /source && tar -czf /backup/data.tar.gz . && test -s /backup/data.tar.gz'
fi
APPLIED=1
tar -C "$SOURCE" -cf - --exclude='./.env' . | tar -C "$APP" -xf -
rm -f "$APP"/deploy/install-v1.*-full.sh "$APP/deploy/upgrade-agent-on-vps.sh" "$APP/setup.sh"
cd "$APP"
echo '[5/6] Configuring admin login and built-in updates...'
docker compose run --rm --no-deps -T manager python -m manager.cli provision-env
python3 - <<'PY'
from pathlib import Path
p=Path('.env')
s=p.read_text().splitlines()
p.write_text('\n'.join('XPPN_ADMIN_PASSWORD=' if x.startswith('XPPN_ADMIN_PASSWORD=') else x for x in s)+'\n')
p.chmod(0o600)
PY
if [[ -d /run/systemd/system ]]; then
  bash deploy/install-updater.sh https://github.com/chapaayy/Manager.git
else
  sed -i 's/^XPPN_UPDATE_ENABLED=.*/XPPN_UPDATE_ENABLED=false/' .env
fi
docker compose --profile public up -d --no-build manager caddy
READY=0
for _ in $(seq 1 40); do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8787/api/me",timeout=2)' >/dev/null 2>&1; then
    READY=1;break
  fi
  sleep 2
done
[[ "$READY" == 1 ]] || { docker compose logs --tail=80 manager >&2; false; }
trap - ERR
echo "[6/6] Ready: https://$(sed -n 's/^XPPN_DOMAIN=//p' .env | head -1)"
echo 'Login with the credentials entered in .env; no extra commands required'
python3 - "$BACKUP/.env" <<'PY'
import sys
from pathlib import Path
p=Path(sys.argv[1]);s=p.read_text().splitlines()
p.write_text('\n'.join('XPPN_ADMIN_PASSWORD=' if x.startswith('XPPN_ADMIN_PASSWORD=') else x for x in s)+'\n')
p.chmod(0o600)
PY
echo "Backup: $BACKUP"
