#!/usr/bin/env bash
# Root-only worker. A web request may trigger an update but cannot supply any command, path, or URL.
set -Eeuo pipefail
umask 077
[[ "$EUID" == 0 ]] || exit 1
source /etc/xppn-manager-updater.env
: "${XPPN_GIT_URL:?Configure fixed GitHub URL}"
BRANCH="${XPPN_GIT_BRANCH:-main}"
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]{1,80}$ && "$BRANCH" != -* ]] || exit 1
[[ "$XPPN_GIT_URL" =~ ^(git@github.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git|https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git)$ ]] || exit 1
for tool in git docker python3 flock tar; do command -v "$tool" >/dev/null || exit 1; done
BASE=/opt/xppn-manager
ROOT=/opt/xppn-manager-updater
# The systemd unit uses ProtectHome=yes; Docker must not write to /root/.docker.
export DOCKER_CONFIG="${DOCKER_CONFIG:-$ROOT/docker-config}"
install -d -m 0700 "$DOCKER_CONFIG"
VOLUME="$(docker volume inspect --format '{{.Mountpoint}}' xppn-manager_manager-data)"
[[ -d "$VOLUME" && -f "$BASE/.env" ]] || exit 1
mkdir -p "$ROOT/releases" "$ROOT/backups"
chmod 700 "$ROOT" "$ROOT/releases" "$ROOT/backups"
exec 8>"$ROOT/.lock"
flock -n 8 || exit 0
[[ -s "$VOLUME/update-request.json" ]] || exit 0
mv "$VOLUME/update-request.json" "$ROOT/request.processing"
report() {
  STATUS="$1" DETAIL="$2" COMMIT="${3:-}" VOLUME="$VOLUME" python3 - <<'PYTHON_REPORT'
import json,os,time,pathlib
p=pathlib.Path(os.environ['VOLUME'])
q=p/'update-status.tmp'
q.write_text(json.dumps({'status':os.environ['STATUS'],'detail':os.environ['DETAIL'][:450],
                         'commit':os.environ.get('COMMIT',''),'updated_at':int(time.time())}))
q.chmod(0o644)
q.replace(p/'update-status.json')
PYTHON_REPORT
}
fail() { report error 'Update failed; inspect the updater service journal'; rm -f "$ROOT/request.processing"; exit 1; }
trap fail ERR
report running 'Fetching fixed GitHub source'
if [[ ! -d "$ROOT/source/.git" ]]; then
  git clone --no-checkout --filter=blob:none "$XPPN_GIT_URL" "$ROOT/source"
fi
[[ "$(git -C "$ROOT/source" remote get-url origin)" == "$XPPN_GIT_URL" ]] || exit 1
git -C "$ROOT/source" fetch --depth=1 origin "$BRANCH"
SHA="$(git -C "$ROOT/source" rev-parse FETCH_HEAD)"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 1
NEW="$ROOT/releases/$SHA"
if [[ ! -d "$NEW" ]]; then
  mkdir -p "$NEW"
  git -C "$ROOT/source" archive "$SHA" | tar -x -C "$NEW"
fi
[[ -f "$NEW/manager/app.py" && -f "$NEW/docker-compose.yml" && -f "$NEW/manager/Dockerfile" && ! -f "$NEW/.env" ]] || exit 1
cp -p "$BASE/.env" "$NEW/.env"
chmod 600 "$NEW/.env"
OLD="$BASE"
if [[ -s "$ROOT/current" ]]; then OLD="$(cat "$ROOT/current")"; fi
[[ -f "$OLD/docker-compose.yml" && -f "$OLD/.env" ]] || exit 1
BACKUP="$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)-${SHA:0:10}"
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
cp -p "$BASE/.env" "$BACKUP/.env"
# Build first, with the currently running Manager still serving requests.
# A failed build should NOT take the website offline.
report running 'Building new Manager; current version remains online' "$SHA"
docker compose --project-name xppn-manager -f "$NEW/docker-compose.yml" --env-file "$NEW/.env" build manager
# Stop Manager only after the candidate Docker image has successfully built.
rollback(){
  code=$?
  report error "Update failed; restoring backed-up data and previous release: $BACKUP" "$SHA"
  # A new release may have altered the SQLite schema before health checks failed.
  # Restore a known-good database snapshot before booting the old application.
  docker compose --project-name xppn-manager -f "$NEW/docker-compose.yml" --env-file "$NEW/.env" stop manager || true
  if [[ -s "$BACKUP/data.tar.gz" ]]; then
    docker run --rm --network none -v xppn-manager_manager-data:/data -v "$BACKUP":/backup:ro alpine:3.20 \
      sh -eu -c 'cd /data && find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + && tar -xzf /backup/data.tar.gz' || true
  fi
  docker compose --project-name xppn-manager -f "$OLD/docker-compose.yml" --env-file "$OLD/.env" up -d --build --no-deps manager || true
  rm -f "$ROOT/request.processing"
  exit "$code"
}
trap rollback ERR
docker compose --project-name xppn-manager -f "$OLD/docker-compose.yml" --env-file "$OLD/.env" stop manager
docker run --rm --network none -v xppn-manager_manager-data:/source:ro -v "$BACKUP":/backup alpine:3.20 sh -eu -c 'cd /source && tar -czf /backup/data.tar.gz . && test -s /backup/data.tar.gz'
docker compose --project-name xppn-manager -f "$NEW/docker-compose.yml" --env-file "$NEW/.env" up -d --no-build --no-deps --force-recreate manager
READY=0
for i in $(seq 1 25); do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8787/api/me",timeout=2)' >/dev/null 2>&1; then READY=1;break;fi
  sleep 2
done
[[ "$READY" == 1 ]] || exit 1
printf '%s\n' "$NEW" > "$ROOT/current"
report success 'Manager updated, session secret and data preserved' "$SHA"
rm -f "$ROOT/request.processing"
trap - ERR
