#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
trap 'rc=$?; echo "[XPPN Bootstrap] Failed at line ${LINENO}, exit code ${rc}" >&2' ERR
echo "[XPPN Bootstrap] Checking base dependencies"
[[ "$(id -u)" -eq 0 ]] || { echo 'root required' >&2; exit 1; }
[[ -n "${XPPN_PACKAGE:-}" && -f "${XPPN_PACKAGE}" && -n "${XPPN_INPUT_ENV:-}" && -f "${XPPN_INPUT_ENV}" && -n "${XPPN_HELPER_KEY:-}" && -f "${XPPN_HELPER_KEY}" ]] || exit 1
# Preexisting installs are not touched. Acquire distro packages only when needed.
command -v python3 >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y python3; }
if ! command -v docker >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 || \
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin
fi
echo "[XPPN Bootstrap] Starting Docker"
systemctl enable --now docker
docker info >/dev/null
echo "[XPPN Bootstrap] Installing agent files and helper"
mkdir -p /opt/xppn-agent /var/backups/xppn /run/xppn-agent
chmod 700 /opt/xppn-agent /var/backups/xppn
tar -xzf "$XPPN_PACKAGE" -C /opt/xppn-agent
# Agent Compose lives under agent/ in the transmitted bundle. Compose, however,
# is invoked from /opt/xppn-agent; stage the manifest at the project root so
# `build: ./agent` resolves to the actual Dockerfile directory.
SOURCE_COMPOSE=/opt/xppn-agent/agent/docker-compose.yml
TARGET_COMPOSE=/opt/xppn-agent/docker-compose.yml
[[ -f "$SOURCE_COMPOSE" && -f /opt/xppn-agent/agent/Dockerfile ]] || {
  echo '[XPPN Bootstrap] Agent Compose/Dockerfile missing from transferred bundle' >&2
  exit 1
}
install -m 600 "$SOURCE_COMPOSE" "$TARGET_COMPOSE"
install -m 600 "$XPPN_INPUT_ENV" /opt/xppn-agent/agent.env
install -m 600 "$XPPN_HELPER_KEY" /opt/xppn-agent/helper.key
install -m 644 /opt/xppn-agent/bootstrap/xppn-helper.service /etc/systemd/system/xppn-helper.service
install -m 644 /opt/xppn-agent/bootstrap/xppn-node-firewall.service /etc/systemd/system/xppn-node-firewall.service
systemctl daemon-reload
systemctl enable --now xppn-helper.service
for n in $(seq 1 30); do
  [[ -S /run/xppn-agent/helper.sock ]] && break
  sleep 1
done
[[ -S /run/xppn-agent/helper.sock ]] || { echo 'host helper socket failed' >&2; exit 1; }
echo "[XPPN Bootstrap] Building and starting Docker agent"
cd /opt/xppn-agent
# Fail with a clear message before attempting to build a container.
docker compose -f "$TARGET_COMPOSE" config -q || {
  echo '[XPPN Bootstrap] Agent Compose validation failed' >&2
  exit 1
}
docker compose -f "$TARGET_COMPOSE" up -d --build xppn-agent
# `up` may report success while the process crashes immediately.
container_running="$(docker inspect --format '{{.State.Running}}' xppn-agent 2>/dev/null || true)"
[[ "$container_running" == 'true' ]] || {
  echo '[XPPN Bootstrap] Agent container did not remain running' >&2
  exit 1
}
rm -f "$XPPN_INPUT_ENV" "$XPPN_PACKAGE" "$XPPN_HELPER_KEY"
echo 'XPPN agent deployed successfully'
