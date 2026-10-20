#!/usr/bin/env bash
# Inspect metadata for Agentmux files or explicit --path selections; never read keys.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../taskmgmt/provider_setup.py" check-exposure "$@"
