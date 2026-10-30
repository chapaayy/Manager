#!/usr/bin/env bash
# XPPN Manager 1.1.3, safe incremental update from the FULL archive.
set -Eeuo pipefail
APP=/opt/xppn-manager
ARCHIVE=/tmp/xppn-manager-v1.1.3-alpha-full.tar.gz
BACKUP_ROOT=/root/xppn-manager-backups

if [[ "${EUID}" -ne 0 ]]; then
  echo 'Run this installer as root.' >&2; exit 1
fi
if [[ ! -s "$ARCHIVE" || ! -f "$APP/.env" ]]; then
  echo "Missing $ARCHIVE or $APP/.env. This updates an existing Manager only." >&2; exit 1
fi
if ! tar -tzf "$ARCHIVE" >/dev/null; then
  echo 'Archive failed integrity/readability check.' >&2; exit 1
fi
cd "$APP"
CID="$(docker compose ps -a -q manager)"
if [[ -z "$CID" ]]; then
  echo 'Existing Manager container not found; stopping to avoid overwriting another installation.' >&2
  exit 1
fi
DATA_VOL="$(docker inspect "$CID" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')"
if [[ -z "$DATA_VOL" ]]; then
  echo 'Cannot identify existing /data named volume. No changes made.' >&2
  exit 1
fi
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/v1.1.3-$STAMP"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"
cp -a "$APP/.env" "$BACKUP_DIR/.env"
chmod 600 "$BACKUP_DIR/.env"

echo 'Stopping Manager for consistent SQLite backup. Caddy continues running.'
docker compose stop manager
restore_on_error() {
  echo 'Update failed. Trying to restart the existing Manager container.' >&2
  (cd "$APP" && docker compose start manager) || true
  echo "Backup: $BACKUP_DIR" >&2
}
trap restore_on_error ERR

docker run --rm --network none \
  -v "$DATA_VOL:/source:ro" \
  -v "$BACKUP_DIR:/backup" \
  alpine:3.20 sh -eu -c 'cd /source && tar -czf /backup/manager-data.tar.gz . && test -s /backup/manager-data.tar.gz'

echo 'Applying complete release, preserving .env and Docker volumes.'
tar -xzf "$ARCHIVE" --strip-components=1 -C "$APP"
test -s "$APP/.env"
docker compose --profile public up -d --build --no-deps manager
trap - ERR

echo "Updated XPPN Manager from full archive. Backup: $BACKUP_DIR"
docker compose ps manager
