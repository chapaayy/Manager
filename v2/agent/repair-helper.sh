#!/usr/bin/env bash
# Repair ONLY the first-install agent's systemd sandbox. No Remnawave changes.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 51
UNIT=node-manager-agent.service
DROP=/etc/systemd/system/node-manager-agent.service.d
DEST="$DROP/20-helper-permissions.conf"
STAGE=preflight
trap 'rc=$?; printf "AGENT_REPAIR_FAILURE:%s:%s\n" "$STAGE" "$rc"; exit "$rc"' ERR
test -s /etc/systemd/system/node-manager-agent.service
test -x /usr/local/bin/node-manager-agent
test -x /usr/local/libexec/node-manager-helper
test -s /etc/node-manager/agent.env
test -x /usr/bin/sudo
id nodemanager >/dev/null
test -s /etc/sudoers.d/nodemanager-agent
visudo -c -f /etc/sudoers.d/nodemanager-agent >/dev/null
STAGE=backup
install -d -m 0755 "$DROP"
if [[ -e "$DEST" ]]; then
  cp -p -- "$DEST" "$DROP/.20-helper-permissions.previous"
  HAD_OLD=1
else
  HAD_OLD=0
fi
STAGE=write
TMP="$(mktemp "$DROP/.helper-permissions.XXXXXXXX")"
cat >"$TMP" <<'UNIT'
[Service]
# The original agent unit accidentally cleared all Linux capabilities.
# This restores the capabilities sudo needs, while the Go process still
# runs as an unprivileged system user with no ambient capabilities.
CapabilityBoundingSet=~
# Root helper needs writable Nginx config and sudo runtime state.
ReadWritePaths=/opt/nginx /run
# Validate helper operation in exactly the same sandbox as the agent.
ExecStartPost=/usr/bin/sudo -n /usr/local/libexec/node-manager-helper service.status
UNIT
chmod 0644 "$TMP"
mv -f "$TMP" "$DEST"
restore() {
  if [[ "$HAD_OLD" == 1 ]]; then
    mv -f "$DROP/.20-helper-permissions.previous" "$DEST"
  else
    rm -f "$DEST"
  fi
  systemctl daemon-reload || true
  systemctl restart "$UNIT" >/dev/null 2>&1 || true
}
STAGE=service
if ! systemctl daemon-reload || ! systemctl restart "$UNIT" || ! systemctl is-active --quiet "$UNIT"; then
  restore
  printf "AGENT_REPAIR_FAILURE:service:1\n"
  exit 1
fi
STAGE=cleanup
rm -f "$DROP/.20-helper-permissions.previous"
printf "AGENT_REPAIR_SUCCESS\n"
