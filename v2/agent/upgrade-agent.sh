#!/usr/bin/env bash
# Explicit one-time migration of old agent to update-capable version.
# Keep current agent.env, identity and systemd service.
set -Eeuo pipefail
umask 077
stage=/root/.node-manager-agent-upgrade
agent=/usr/local/bin/node-manager-agent
helper=/usr/local/libexec/node-manager-helper
updater=/usr/local/libexec/node-manager-updater
test -f "$agent" && test ! -L "$agent"
test -f "$helper" && test ! -L "$helper"
test -s /etc/node-manager/agent.env
systemctl is-active --quiet node-manager-agent.service
for file in agent-binary agent-helper.py agent-updater.sh; do
  test -s "$stage/$file" && test ! -L "$stage/$file"
done
install -d -m 0700 /var/backups/node-manager-upgrade
install -m 0700 "$agent" /var/backups/node-manager-upgrade/previous-agent
install -m 0700 "$helper" /var/backups/node-manager-upgrade/previous-helper
if test -f "$updater"; then
  install -m 0700 "$updater" /var/backups/node-manager-upgrade/previous-updater
fi
install -d -m 0750 -o nodemanager -g nodemanager /var/lib/node-manager
install -m 0700 "$stage/agent-updater.sh" "$updater"
install -m 0755 "$stage/agent-helper.py" "$helper"
install -m 0755 "$stage/agent-binary" "$agent"
if ! systemctl restart node-manager-agent.service ||
   ! systemctl is-active --quiet node-manager-agent.service; then
  install -m 0755 /var/backups/node-manager-upgrade/previous-agent "$agent"
  install -m 0755 /var/backups/node-manager-upgrade/previous-helper "$helper"
  if test -f /var/backups/node-manager-upgrade/previous-updater; then
    install -m 0700 /var/backups/node-manager-upgrade/previous-updater "$updater"
  else
    rm -f "$updater"
  fi
  systemctl restart node-manager-agent.service || true
  echo AGENT_UPGRADE:rolled-back
  exit 31
fi
rm -rf -- "$stage"
echo AGENT_UPGRADE:restarted
