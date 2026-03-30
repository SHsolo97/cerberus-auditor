#!/usr/bin/env python3
"""
log_improvement.py — Append a structured improvement entry to the skill log.

Usage:
    python3 log_improvement.py --phase <phase> --severity <low|medium|high> \\
        --category <category> --summary "<summary>" [--suggested-fix "<fix>"]

All paths are derived from SKILL_ROOT (resolved from this script's location).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Derive SKILL_ROOT: scripts/log_improvement.py -> cerberus_common/scripts -> cerberus-common -> skill root
SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SKILL_ROOT / "cerberus_common"))

from improvement import append_improvement_entry, utc_now_iso

import uuid


def main() -> int:
    parser = argparse.ArgumentParser(description="Log a structured improvement entry.")
    parser.add_argument("--phase", required=True, help="Phase name (e.g. ast_semantic_index)")
    parser.add_argument("--severity", required=True, choices={"low", "medium", "high"}, help="Severity level")
    parser.add_argument("--category", required=True, help="Category (e.g. runtime_error, missing_coverage)")
    parser.add_argument("--summary", required=True, help="One-line summary of the issue")
    parser.add_argument("--suggested-fix", default="", help="Suggested fix description")
    parser.add_argument("--source", default="manual", help="Source of the entry")
    parser.add_argument("--run-id", default=None, help="Run ID (auto-generated if not provided)")
    args = parser.parse_args()

    entry = {
        "timestamp": utc_now_iso(),
        "run_id": args.run_id or str(uuid.uuid4())[:8],
        "phase": args.phase,
        "severity": args.severity,
        "category": args.category,
        "source": args.source,
        "summary": args.summary,
        "suggested_fix": args.suggested_fix or "Inspect the relevant phase and update the skill.",
        "details": {},
    }

    append_improvement_entry(entry)
    print(f"Logged improvement entry: [{args.severity}] {args.phase}: {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
