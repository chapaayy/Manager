#!/usr/bin/env bash
# XPPN Manager v1.3.0 full release upgrade. Existing installation only.
set -Eeuo pipefail
umask 077
APP=/opt/xppn-manager
ARCHIVE=/tmp/xppn-manager-v1.3.0-alpha-full.tar.gz
BACKUP_ROOT=/root/xppn-manager-backups
[[ ${EUID} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -s "$ARCHIVE" && -f "$APP/.env" ]] || { echo "Missing $ARCHIVE or $APP/.env" >&2; exit 1; }
tar -tzf "$ARCHIVE" >/dev/null
cd "$APP"
CID="$(docker compose ps -a -q manager)"
[[ -n "$CID" ]] || { echo 'Existing Manager container not found; refusing upgrade' >&2; exit 1; }
DATA_VOL="$(docker inspect "$CID" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
[[ -n "$DATA_VOL" ]] || { echo 'Existing data volume missing; refusing upgrade' >&2; exit 1; }
BACKUP_DIR="$BACKUP_ROOT/v1.3.0-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"
cp -p "$APP/.env" "$BACKUP_DIR/.env"
# Source backup before any overwrite. Secrets in .env stored separately.
tar -czf "$BACKUP_DIR/source.tar.gz" --exclude='./.env' --exclude='./.git' -C "$APP" .
test -s "$BACKUP_DIR/source.tar.gz"
STAGE="$(mktemp -d /tmp/xppn-update-v13.XXXXXX)"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
tar -xzf "$ARCHIVE" --strip-components=1 -C "$STAGE"
[[ -s "$STAGE/manager/app.py" && -s "$STAGE/manager/projects.py" && -s "$STAGE/manager/remna_api.py" ]] || exit 1
if command -v python3 >/dev/null; then python3 -m compileall -q "$STAGE/manager" "$STAGE/agent"; fi
[[ ! -f "$STAGE/legacy/installer.env" ]] || { echo 'Secret file accidentally packed; aborting' >&2; exit 1; }
echo "Backups: $BACKUP_DIR"
echo 'Stopping only Manager for consistent SQLite volume backup; Caddy remains online.'
docker compose stop manager
APPLIED=0
rollback() {
  rc=$?
  echo 'Upgrade failed. Restoring previous source and attempting restart.' >&2
  if [[ "$APPLIED" == 1 ]]; then tar -xzf "$BACKUP_DIR/source.tar.gz" -C "$APP" || true; fi
  (cd "$APP" && docker compose --profile public up -d --build --no-deps manager) || true
  echo "Source and database backup: $BACKUP_DIR" >&2
  exit "$rc"
}
trap rollback ERR
docker run --rm --network none -v "$DATA_VOL:/source:ro" -v "$BACKUP_DIR:/backup" alpine:3.20 \
  sh -eu -c 'cd /source && tar -czf /backup/data.tar.gz . && test -s /backup/data.tar.gz'
[[ -s "$BACKUP_DIR/data.tar.gz" ]] || { echo 'Database backup missing' >&2; exit 1; }
APPLIED=1
# Copy only release files. .env and named Docker volumes remain unchanged.
tar -C "$STAGE" -cf - --exclude='.env' . | tar -C "$APP" -xf -
cd "$APP"
docker compose --profile public up -d --build --no-deps manager
# Health check: must be reachable on internal loopback, even unauthenticated.
READY=0
for i in $(seq 1 25); do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8787/api/me",timeout=2)' >/dev/null 2>&1; then READY=1; break; fi
  sleep 2
done
[[ "$READY" == 1 ]] || { echo 'Health check failed; rolling back source' >&2; exit 1; }
trap - ERR
printf '\nXPPN Manager v1.3.0 started. Backups: %s\n' "$BACKUP_DIR"
docker compose ps manager
