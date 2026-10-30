#!/usr/bin/env bash
# The website queues a request; only this root worker updates fixed GitHub code.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
source /etc/xppn-manager-updater.env
: "$XPPN_GIT_URL"
BRANCH="$XPPN_GIT_BRANCH"
[[ $BRANCH =~ ^[A-Za-z0-9._/-]{1,80}$ && $BRANCH != -* ]] || exit 1
[[ $XPPN_GIT_URL =~ ^(git@github.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git|https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git)$ ]] || exit 1
for tool in git docker python3 tar flock; do command -v "$tool" >/dev/null || exit 1; done
APP=/opt/xppn-manager
ROOT=/opt/xppn-manager-updater
VOLUME=xppn-manager_manager-data
export HOME="$ROOT"
export DOCKER_CONFIG="$ROOT/docker-config"
install -d -m 0700 "$ROOT" "$ROOT/docker-config" "$ROOT/releases" "$ROOT/backups"
exec 8>"$ROOT/.lock"
flock -n 8 || exit 0
MOUNT="$(docker volume inspect --format '{{.Mountpoint}}' "$VOLUME")"
[[ -d "$MOUNT" && -s "$APP/.env" ]] || exit 1
[[ -s "$MOUNT/update-request.json" ]] || exit 0
mv "$MOUNT/update-request.json" "$ROOT/request.processing"
report(){
  local status="$1" detail="$2" commit=''
  if [[ $# -ge 3 ]]; then commit="$3"; fi
  STATUS="$status" DETAIL="$detail" COMMIT="$commit" VOLUME="$MOUNT" python3 - <<'PY'
import json,os,time,pathlib
p=pathlib.Path(os.environ['VOLUME']);q=p/'update-status.tmp'
q.write_text(json.dumps({'status':os.environ['STATUS'],'detail':os.environ['DETAIL'][:450],
 'commit':os.environ['COMMIT'],'updated_at':int(time.time())}))
q.chmod(0o644);q.replace(p/'update-status.json')
PY
}
STAGED=0
STOPPED=0
BACKUP=''
OLD_IMAGE=''
rollback(){
  rc=$?
  trap - ERR
  if [[ "$STOPPED" == 1 ]]; then
    docker compose -p xppn-manager -f "$APP/docker-compose.yml" --env-file "$APP/.env" stop manager || true
    if [[ "$STAGED" == 1 && -s "$BACKUP/data.tar.gz" ]]; then
      docker run --rm --network none -v "$VOLUME:/data" -v "$BACKUP:/backup:ro" alpine:3.20 \
        sh -eu -c 'cd /data && find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + && tar -xzf /backup/data.tar.gz' || true
    fi
    if [[ "$STAGED" == 1 && -s "$BACKUP/source.tar.gz" ]]; then
      tar -xzf "$BACKUP/source.tar.gz" -C "$APP" || true
      cp -p "$BACKUP/.env" "$APP/.env" || true
    fi
    if [[ -n "$OLD_IMAGE" ]]; then docker image tag "$OLD_IMAGE" xppn-manager-manager || true; fi
    docker compose -p xppn-manager -f "$APP/docker-compose.yml" --env-file "$APP/.env" \
      up -d --no-build --no-deps manager || true
  fi
  report error 'Update failed; previous version retained/restored. Check updater journal.' || true
  rm -f "$ROOT/request.processing"
  exit "$rc"
}
trap rollback ERR
report running 'Fetching fixed GitHub repository'
if [[ ! -d "$ROOT/source/.git" ]]; then
  git clone --no-checkout --filter=blob:none "$XPPN_GIT_URL" "$ROOT/source"
fi
[[ "$(git -C "$ROOT/source" remote get-url origin)" == "$XPPN_GIT_URL" ]] || exit 1
git -C "$ROOT/source" fetch --depth=1 origin "$BRANCH"
SHA="$(git -C "$ROOT/source" rev-parse FETCH_HEAD)"
[[ $SHA =~ ^[a-f0-9]{40}$ ]] || exit 1
if [[ -f "$ROOT/last-sha" && "$(cat "$ROOT/last-sha")" == "$SHA" ]]; then
  report success 'Already at latest version' "$SHA"
  rm -f "$ROOT/request.processing"
  trap - ERR
  exit 0
fi
NEW="$ROOT/releases/$SHA"
if [[ ! -s "$NEW/manager/app.py" ]]; then
  mkdir -p "$NEW"
  git -C "$ROOT/source" archive "$SHA" | tar -x -C "$NEW"
fi
[[ -s "$NEW/manager/app.py" && -s "$NEW/docker-compose.yml" && -s "$NEW/manager/Dockerfile" && ! -e "$NEW/.env" ]] || exit 1
cp -p "$APP/.env" "$NEW/.env"
chmod 600 "$NEW/.env"
python3 -m compileall -q "$NEW/manager" "$NEW/agent"
bash -n "$NEW/install.sh" "$NEW/deploy/update-worker.sh" "$NEW/deploy/install-updater.sh"
report running 'Building update BEFORE stopping current Manager' "$SHA"
if docker image inspect xppn-manager-manager >/dev/null 2>&1; then
  OLD_IMAGE="xppn-manager:before-web-update-$(date +%s)"
  docker image tag xppn-manager-manager "$OLD_IMAGE"
fi
docker compose -p xppn-manager -f "$NEW/docker-compose.yml" --env-file "$NEW/.env" build manager
BACKUP="$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)-$(printf %.10s "$SHA")"
install -d -m 0700 "$BACKUP"
cp -p "$APP/.env" "$BACKUP/.env"
tar -C "$APP" -czf "$BACKUP/source.tar.gz" --exclude='./.env' --exclude='./.git' .
report running 'Switching to new version' "$SHA"
docker compose -p xppn-manager -f "$APP/docker-compose.yml" --env-file "$APP/.env" stop manager
STOPPED=1
docker run --rm --network none -v "$VOLUME:/source:ro" -v "$BACKUP:/backup" alpine:3.20 \
  sh -eu -c 'cd /source && tar -czf /backup/data.tar.gz . && test -s /backup/data.tar.gz'
STAGED=1
tar -C "$NEW" -cf - --exclude='./.env' . | tar -C "$APP" -xf -
rm -f "$APP"/deploy/install-v1.*-full.sh "$APP/deploy/upgrade-agent-on-vps.sh" "$APP/setup.sh"
docker compose -p xppn-manager -f "$APP/docker-compose.yml" --env-file "$APP/.env" \
  up -d --no-build --no-deps --force-recreate manager
READY=0
for _ in $(seq 1 40); do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8787/api/me",timeout=2)' >/dev/null 2>&1; then
    READY=1;break
  fi
  sleep 2
done
[[ "$READY" == 1 ]] || exit 1
printf '%s\n' "$SHA" > "$ROOT/last-sha"
report success 'Manager updated; sessions and database preserved' "$SHA"
rm -f "$ROOT/request.processing"
trap - ERR
