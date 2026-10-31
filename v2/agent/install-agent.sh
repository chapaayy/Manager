#!/usr/bin/env bash
# First-time SSH bootstrap ONLY. Called after existing Remnawave Node is ready.
set -Eeuo pipefail
umask 077
AGENT_STAGE=preflight
trap 'code=$?; printf "AGENT_FAILURE:%s:%s\n" "$AGENT_STAGE" "$code"; exit "$code"' ERR
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
[[ "$(id -u)" == 0 ]] || exit 51
STAGE=/root/.node-manager-bootstrap
test -s "$STAGE/agent-binary"
test -s "$STAGE/agent-helper.py"
test -s "$STAGE/agent.env"
test -s "$STAGE/agent-uninstall.sh"
command -v apt-get >/dev/null
export DEBIAN_FRONTEND=noninteractive
AGENT_STAGE=dependencies
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
if ! command -v sudo >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq sudo ca-certificates
fi
AGENT_STAGE=user
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
getent group nodemanager >/dev/null || groupadd -r nodemanager
id nodemanager >/dev/null 2>&1 ||
  useradd -r -g nodemanager -M -s /usr/sbin/nologin nodemanager
AGENT_STAGE=files
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
install -d -m 0750 -o root -g nodemanager /etc/node-manager
install -m 0640 -o root -g nodemanager "$STAGE/agent.env" /etc/node-manager/agent.env
install -d -m 0755 /usr/local/libexec
install -m 0755 -o root -g root "$STAGE/agent-helper.py" /usr/local/libexec/node-manager-helper
install -m 0700 -o root -g root "$STAGE/agent-uninstall.sh" /usr/local/libexec/node-manager-uninstall.sh
# Agent was cross-compiled in the Manager image for this VPS architecture.
# No compiler or Go source is needed on the node.
AGENT_STAGE=binary
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
install -m 0755 -o root -g root "$STAGE/agent-binary" /usr/local/bin/node-manager-agent
AGENT_STAGE=sudoers
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
cat >/etc/sudoers.d/nodemanager-agent <<'SUDO'
Defaults:nodemanager !requiretty
nodemanager ALL=(root) NOPASSWD: /usr/local/libexec/node-manager-helper *
SUDO
chmod 0440 /etc/sudoers.d/nodemanager-agent
visudo -c -f /etc/sudoers.d/nodemanager-agent >/dev/null
AGENT_STAGE=systemd
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
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
# Fail setup immediately if privilege elevation is broken inside this sandbox.
ExecStartPost=/usr/bin/sudo -n /usr/local/libexec/node-manager-helper service.status
Restart=always
RestartSec=5
WorkingDirectory=/
# Privilege boundary: unprivileged Go agent -> sudo allowlisted, root-owned
# helper. Systemd namespace/seccomp hardening is deliberately NOT enabled here:
# several directives imply NoNewPrivileges/nosuid and break sudo setuid.
# Use a separate root socket service to reintroduce sandboxing later.
NoNewPrivileges=no
AmbientCapabilities=
UMask=0077
MemoryMax=256M
[Install]
WantedBy=multi-user.target
UNIT
AGENT_STAGE=service
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
systemctl daemon-reload
systemctl enable --now node-manager-agent.service
systemctl is-active --quiet node-manager-agent.service
AGENT_STAGE=cleanup
printf "AGENT_STEP:%s\n" "$AGENT_STAGE"
rm -rf "$STAGE"
printf "AGENT_SUCCESS:installed\n"
