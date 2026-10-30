#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")"
[[ ! -f .env ]] || { echo '.env exists: refusing to overwrite'; exit 1; }
command -v python3 >/dev/null || { echo 'Install python3 first'; exit 1; }
read -rp 'Manager DNS hostname (e.g. manager.example.com): ' host
if [[ ! "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then echo 'Invalid DNS name';exit 1;fi
HOST_NAME="$host" python3 - <<'PY'
import os,secrets,base64
from pathlib import Path
h=os.environ['HOST_NAME'].lower()
key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
s=f'''XPPN_DOMAIN={h}
XPPN_PUBLIC_URL=https://{h}
XPPN_ALLOWED_HOSTS={h},localhost,127.0.0.1
XPPN_SECURE_COOKIES=true
XPPN_SESSION_SECRET={secrets.token_urlsafe(48)}
XPPN_DATA_KEY={key}
XPPN_ALLOW_PRIVATE_SSH=false
'''
Path('.env').write_text(s)
Path('.env').chmod(0o600)
PY
echo '.env created (mode 600).'
echo 'Next: docker compose build manager && docker compose run --rm manager python -m manager.cli init'
echo 'Then: docker compose --profile public up -d'
