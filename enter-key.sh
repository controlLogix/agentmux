#!/usr/bin/env bash
# Enter a local xAI key without echoing it or passing it as a command argument.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/taskmgmt/provider_setup.py" enter-key "$@"
