#!/usr/bin/env bash
set -euo pipefail
PYTHONPATH="$(cd "$(dirname "$0")" && pwd):$PYTHONPATH"
PHASE_NAME="${1:-}"
SCRIPT_PATH="${2:-}"
TARGET_DIR="${3:-.}"
if [[ -z "${PHASE_NAME}" || -z "${SCRIPT_PATH}" ]]; then
  echo "Usage: $0 <phase_name> <script_path> [target_dir]" >&2
  exit 1
fi
python3 "$(dirname "$0")/../scripts/preflight_or_repair.py" \
  --phase-name "${PHASE_NAME}" --script-path "${SCRIPT_PATH}" --target-dir "${TARGET_DIR}"
