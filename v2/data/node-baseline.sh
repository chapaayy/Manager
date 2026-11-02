#!/usr/bin/env bash
# Compatibility wrapper. All baseline logic lives in the modular root helper.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 51
HELPER=/usr/local/libexec/node-manager-helper
if [[ -x "$HELPER" ]]; then
  exec "$HELPER" security.bootstrap </dev/null
fi
# Fresh-install staging path, before the Agent has been installed permanently.
test -s /root/.xppn-pending/agent-helper.py
test -s /root/.xppn-pending/agent-helperlib.zip
exec python3 /root/.xppn-pending/agent-helper.py security.bootstrap </dev/null
