#!/usr/bin/env bash
# Offline presence check only. Exit 2 means live access remains unverified.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/taskmgmt/provider_setup.py" verify-grok "$@"
