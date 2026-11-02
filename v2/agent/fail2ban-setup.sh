#!/usr/bin/env bash
# Compatibility worker: the actual Fail2Ban logic lives in the root helper.
set -Eeuo pipefail
umask 077
admin="${1:-}"
[[ "$(id -u)" == 0 ]] || exit 51
test -x /usr/local/libexec/node-manager-helper
test -s /usr/local/libexec/node-manager-helperlib.zip
unset SUDO_USER SUDO_UID SUDO_GID
payload="$(python3 - "$admin" <<'PY'
import json,sys
print(json.dumps({"admin_ip":sys.argv[1]},separators=(",",":")))
PY
)"
printf '%s' "$payload" |
  /usr/local/libexec/node-manager-helper security.fail2ban.bootstrap
