#!/usr/bin/env bash
set -euo pipefail
PYTHONPATH="$(cd "$(dirname "$0")" && pwd):$PYTHONPATH"
python3 "$(dirname "$0")/../scripts/init_workspace.py" "$@"
