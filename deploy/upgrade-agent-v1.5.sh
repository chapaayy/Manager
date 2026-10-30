#!/usr/bin/env bash
# Upgrades only the XPPN agent/helper code on an already enrolled VPS.
# Never replaces agent.env, helper.key, node configuration, Docker images of other services.
set -Eeuo pipefail
umask 077
ARCHIVE="${1:-/tmp/xppn-manager-v1.5.0-alpha-full.tar.gz}"
BASE=/opt/xppn-agent
[[ "$EUID" == 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -s "$ARCHIVE" && -s "$BASE/agent.env" && -s "$BASE/helper.key" && -s "$BASE/docker-compose.yml" ]] || { echo 'XPPN agent or package missing; no changes made' >&2; exit 1; }
[[ -f "$BASE/agent/helper.py" && -f "$BASE/agent/agent.py" ]] || { echo 'Existing agent sources not found; refusing migration' >&2; exit 1; }
python3 -m py_compile "$BASE/agent/helper.py"
for name in xppn-agent xppn-helper.service; do :; done
BACKUP="/var/backups/xppn/agent-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP";chmod 700 "$BACKUP"
cp -p "$BASE/agent/agent.py" "$BASE/agent/helper.py" "$BASE/agent/Dockerfile" "$BACKUP/"
cp -p "$BASE/docker-compose.yml" "$BACKUP/docker-compose.yml"
STAGING=$(mktemp -d)
cleanup(){ rm -rf "$STAGING"; }
trap cleanup EXIT
tar -xzf "$ARCHIVE" --strip-components=1 -C "$STAGING"
for f in agent/agent.py agent/helper.py agent/Dockerfile; do [[ -s "$STAGING/$f" ]] || { echo "Missing $f" >&2; exit 1; }; done
python3 -m py_compile "$STAGING/agent/helper.py" "$STAGING/agent/agent.py"
FAILED=0
rollback(){
 rc=$?
 echo 'Upgrade failed. Restoring prior agent code.' >&2
 cp -p "$BACKUP/agent.py" "$BASE/agent/agent.py" || true
 cp -p "$BACKUP/helper.py" "$BASE/agent/helper.py" || true
 cp -p "$BACKUP/Dockerfile" "$BASE/agent/Dockerfile" || true
 (systemctl restart xppn-helper.service && cd "$BASE" && docker compose -f docker-compose.yml up -d --build xppn-agent) || true
 exit "$rc"
}
trap rollback ERR
cp -p "$STAGING/agent/agent.py" "$STAGING/agent/helper.py" "$STAGING/agent/Dockerfile" "$BASE/agent/"
systemctl restart xppn-helper.service
for i in $(seq 1 15); do [[ -S /run/xppn-agent/helper.sock ]] && break; sleep 1; done
[[ -S /run/xppn-agent/helper.sock ]] || { echo 'Helper failed after upgrade' >&2; exit 1; }
cd "$BASE"
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build xppn-agent
[[ "$(docker inspect -f '{{.State.Running}}' xppn-agent)" == true ]] || { echo 'Agent failed to stay running' >&2;exit 1; }
trap - ERR
echo "XPPN Agent upgraded. Backup: $BACKUP"
echo 'No VPN-node or Nginx container was restarted.'
