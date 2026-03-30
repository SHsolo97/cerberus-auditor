#!/usr/bin/env bash
set -euo pipefail
PYTHONPATH="$(cd "$(dirname "$0")" && pwd):$PYTHONPATH"
TARGET_DIR="${1:-.}"
python3 "$(dirname "$0")/../scripts/build_semantic_index.py" --target-dir "${TARGET_DIR}"
