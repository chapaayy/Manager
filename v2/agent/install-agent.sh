#!/usr/bin/env bash
# First-time SSH bootstrap ONLY. Called after existing Remnawave Node is ready.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 51
STAGE=/root/.node-manager-bootstrap
test -s "$STAGE/agent-binary"
test -s "$STAGE/agent-helper.py"
test -s "$STAGE/agent.env"
command -v apt-get >/dev/null
export DEBIAN_FRONTEND=noninteractive
if ! command -v sudo >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq sudo ca-certificates
fi
getent group nodemanager >/dev/null || groupadd -r nodemanager
id nodemanager >/dev/null 2>&1 ||
  useradd -r -g nodemanager -M -s /usr/sbin/nologin nodemanager
install -d -m 0750 -o root -g nodemanager /etc/node-manager
install -m 0640 -o root -g nodemanager "$STAGE/agent.env" /etc/node-manager/agent.env
install -d -m 0755 /usr/local/libexec
install -m 0755 -o root -g root "$STAGE/agent-helper.py" /usr/local/libexec/node-manager-helper
# Agent was cross-compiled in the Manager image for this VPS architecture.
# No compiler or Go source is needed on the node.
install -m 0755 -o root -g root "$STAGE/agent-binary" /usr/local/bin/node-manager-agent
cat >/etc/sudoers.d/nodemanager-agent <<'SUDO'
Defaults:nodemanager !requiretty
nodemanager ALL=(root) NOPASSWD: /usr/local/libexec/node-manager-helper *
SUDO
chmod 0440 /etc/sudoers.d/nodemanager-agent
visudo -c -f /etc/sudoers.d/nodemanager-agent >/dev/null
cat >/etc/systemd/system/node-manager-agent.service <<'UNIT'
[Unit]
Description=Node Manager Agent (outbound HTTPS)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=nodemanager
Group=nodemanager
EnvironmentFile=/etc/node-manager/agent.env
ExecStart=/usr/local/bin/node-manager-agent
Restart=always
RestartSec=5
WorkingDirectory=/
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryMax=120M
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now node-manager-agent.service
systemctl is-active --quiet node-manager-agent.service
rm -rf "$STAGE"
