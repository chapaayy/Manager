#!/usr/bin/env bash
# Compatibility wrapper. All baseline logic lives in the modular root helper.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 51
if [[ -s /usr/local/libexec/node-manager-helperlib.zip ]]; then
  exec env PYTHONPATH=/usr/local/libexec/node-manager-helperlib.zip python3 - <<'PY'
import json
from helperlib.security_service import bootstrap_security
print(json.dumps(bootstrap_security({}),separators=(",",":")))
PY
fi
# Fresh-install staging path before the Agent/helper has been installed.
test -s /root/.xppn-pending/agent-helper.py
test -s /root/.xppn-pending/agent-helperlib.zip
exec python3 /root/.xppn-pending/agent-helper.py security.bootstrap </dev/null
