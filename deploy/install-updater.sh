#!/usr/bin/env bash
# Run once as root on the manager VPS. Requires a GitHub repository and its SSH deploy key.
set -Eeuo pipefail
umask 077
[[ "$EUID" == 0 ]] || exit 1
[[ $# -eq 1 ]] || { echo 'Usage: sudo bash deploy/install-updater.sh git@github.com:OWNER/xppn-manager.git'; exit 1; }
[[ "$1" =~ ^(git@github.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git|https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git)$ ]] || exit 1
[[ -f /opt/xppn-manager/.env ]] || exit 1
mkdir -p /opt/xppn-manager-updater
install -m 0700 "$(dirname "$0")/update-worker.sh" /opt/xppn-manager-updater/update-worker.sh
printf 'XPPN_GIT_URL=%q\nXPPN_GIT_BRANCH=main\n' "$1" > /etc/xppn-manager-updater.env
chmod 600 /etc/xppn-manager-updater.env
cat > /etc/systemd/system/xppn-manager-updater.service <<'UNIT'
[Unit]
Description=XPPN fixed-repository update worker
Requires=docker.service
After=docker.service
[Service]
Type=oneshot
ExecStart=/opt/xppn-manager-updater/update-worker.sh
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
UNIT
cat > /etc/systemd/system/xppn-manager-updater.timer <<'UNIT'
[Unit]
Description=XPPN Manager update checks
[Timer]
OnBootSec=30sec
OnUnitActiveSec=45sec
AccuracySec=10sec
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now xppn-manager-updater.timer
if ! grep -q '^XPPN_UPDATE_ENABLED=' /opt/xppn-manager/.env; then
  printf '\nXPPN_UPDATE_ENABLED=true\n' >> /opt/xppn-manager/.env
else
  sed -i 's/^XPPN_UPDATE_ENABLED=.*/XPPN_UPDATE_ENABLED=true/' /opt/xppn-manager/.env
fi
chmod 600 /opt/xppn-manager/.env
echo 'Updater service installed. Restart manager container once to load XPPN_UPDATE_ENABLED=true.'
