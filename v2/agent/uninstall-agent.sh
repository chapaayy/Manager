#!/usr/bin/env bash
# Fixed, root-owned post-acknowledgement self-removal. Never supplied by UI.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 1
test -s /var/lib/node-manager/cleanup-ready
test -f /etc/node-manager/agent.env
# The agent already acknowledged scheduling before this timer activates.
systemctl disable --now node-manager-agent.service || true
rm -f /etc/systemd/system/node-manager-agent.service
rm -rf /etc/systemd/system/node-manager-agent.service.d
rm -f /etc/sudoers.d/nodemanager-agent
rm -f /usr/local/bin/node-manager-agent
rm -f /usr/local/libexec/node-manager-helper
rm -rf /etc/node-manager /var/lib/node-manager
systemctl daemon-reload
# No global Docker, system SSH or OS packages are removed.
userdel nodemanager 2>/dev/null || true
groupdel nodemanager 2>/dev/null || true
rm -f /usr/local/libexec/node-manager-uninstall.sh
