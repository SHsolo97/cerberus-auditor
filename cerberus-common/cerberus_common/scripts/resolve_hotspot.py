#!/usr/bin/env python3
"""
resolve_hotspot.py — Mark a hotspot as resolved or reopen a previously resolved one.

Usage:
    # Resolve:
    python3 resolve_hotspot.py --fingerprint <fp> --resolution-note "<note>" \\
        --resolved-by <name> [--summary "<original summary>"]

    # Reopen:
    python3 resolve_hotspot.py --fingerprint <fp> --reopen
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Derive SKILL_ROOT: scripts/resolve_hotspot.py -> cerberus_common/scripts -> cerberus-common -> skill root
SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SKILL_ROOT / "cerberus_common"))

from improvement import resolve_hotspot, reopen_hotspot


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve or reopen a skill improvement hotspot.")
    parser.add_argument("--fingerprint", required=True, help="Hotspot fingerprint to resolve/reopen")
    parser.add_argument("--resolution-note", help="Resolution note (required when resolving)")
    parser.add_argument("--resolved-by", help="Who resolved this (required when resolving)")
    parser.add_argument("--resolved-in-run-id", help="Run ID in which this was resolved")
    parser.add_argument("--summary", help="Original summary (auto-looked up if not provided)")
    parser.add_argument("--reopen", action="store_true", help="Reopen a previously resolved hotspot")
    args = parser.parse_args()

    if args.reopen:
        reopen_hotspot(fingerprint=args.fingerprint)
        print(f"Reopened hotspot: {args.fingerprint}")
        return 0

    if not args.resolution_note or not args.resolved_by:
        print("ERROR: --resolution-note and --resolved-by are required when resolving.", file=sys.stderr)
        return 1

    resolve_hotspot(
        fingerprint=args.fingerprint,
        resolution_note=args.resolution_note,
        resolved_by=args.resolved_by,
        resolved_in_run_id=args.resolved_in_run_id,
        summary=args.summary,
    )
    print(f"Resolved hotspot: {args.fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
