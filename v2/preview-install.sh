#!/usr/bin/env bash
# Compatibility wrapper. The old "preview" name is retired.
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "preview-install.sh переименован в dev-install.sh; запускаю изолированный dev-режим." >&2
exec bash "$SCRIPT_DIR/dev-install.sh" "$@"
