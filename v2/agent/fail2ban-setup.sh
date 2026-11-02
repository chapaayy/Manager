#!/usr/bin/env bash
# Root-only compatibility worker. It imports one fixed helper function directly;
# this script is not present in the Agent sudoers allowlist.
set -Eeuo pipefail
umask 077
admin="${1:-}"
[[ "$(id -u)" == 0 ]] || exit 51
test -s /usr/local/libexec/node-manager-helperlib.zip
exec env PYTHONPATH=/usr/local/libexec/node-manager-helperlib.zip   python3 - "$admin" <<'PY'
import json
import sys
from helperlib.security_fail2ban import bootstrap_fail2ban

result=bootstrap_fail2ban({"admin_ip":sys.argv[1]})
print(json.dumps(result,separators=(",",":")))
PY
