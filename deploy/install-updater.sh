#!/usr/bin/env bash
# Internal component: install.sh invokes automatically; no user commands.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
[[ $# == 1 ]] || { echo 'Fixed GitHub URL required' >&2; exit 1; }
[[ $1 =~ ^(git@github.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git|https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git)$ ]] || exit 1
[[ -f /opt/xppn-manager/.env ]] || exit 1
install -d -m 0700 /opt/xppn-manager-updater /opt/xppn-manager-updater/docker-config
install -m 0700 "$(dirname "$0")/update-worker.sh" /opt/xppn-manager-updater/update-worker.sh
printf 'XPPN_GIT_URL=%q\nXPPN_GIT_BRANCH=main\n' "$1" > /etc/xppn-manager-updater.env
chmod 600 /etc/xppn-manager-updater.env
cat > /etc/systemd/system/xppn-manager-updater.service <<'UNIT'
[Unit]
Description=XPPN Manager GitHub one-click update worker
Requires=docker.service
After=docker.service
[Service]
Type=oneshot
ExecStart=/opt/xppn-manager-updater/update-worker.sh
User=root
Environment=HOME=/opt/xppn-manager-updater
Environment=DOCKER_CONFIG=/opt/xppn-manager-updater/docker-config
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
UNIT
cat > /etc/systemd/system/xppn-manager-updater.timer <<'UNIT'
[Unit]
Description=XPPN Manager update requests
[Timer]
OnBootSec=30sec
OnUnitActiveSec=45sec
AccuracySec=10sec
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now xppn-manager-updater.timer
